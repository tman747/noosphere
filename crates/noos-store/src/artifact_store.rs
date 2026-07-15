//! Physically isolated, independently-failing durable artifact storage.
//!
//! The consensus [`crate::Store`] never opens, owns, snapshots, or accounts
//! these paths. Visibility is an atomic per-artifact index transition after
//! share durability and an artifact-only WAL record are synced.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub type ArtifactKey = [u8; 32];

#[derive(Clone, Debug)]
pub struct ArtifactStoreConfig {
    pub root: PathBuf,
    pub consensus_root: PathBuf,
    pub segments: PathBuf,
    pub wal: PathBuf,
    pub index: PathBuf,
    pub staging: PathBuf,
    pub quota_bytes: u64,
    pub segment_size_bytes: u64,
    pub max_concurrency: u16,
    pub io_bytes_per_second: u64,
}

impl ArtifactStoreConfig {
    #[must_use]
    pub fn under(
        root: impl Into<PathBuf>,
        consensus_root: impl Into<PathBuf>,
        quota_bytes: u64,
    ) -> Self {
        let root = root.into();
        Self {
            segments: root.join("segments"),
            wal: root.join("wal"),
            index: root.join("index"),
            staging: root.join("staging"),
            root,
            consensus_root: consensus_root.into(),
            quota_bytes,
            segment_size_bytes: 64 * 1024 * 1024,
            max_concurrency: 1,
            io_bytes_per_second: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactFailpoint {
    AfterSegmentSync,
    AfterWalSync,
    BeforeIndexRename,
}

#[derive(Debug)]
pub enum ArtifactStoreError {
    Io {
        op: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    PathOverlap {
        left: PathBuf,
        right: PathBuf,
    },
    InvalidConfig(&'static str),
    QuotaExceeded {
        used: u64,
        requested: u64,
        quota: u64,
    },
    InvalidShare(&'static str),
    NotFound,
    NotPublished,
    Corrupt {
        path: PathBuf,
        reason: &'static str,
    },
    Injected(ArtifactFailpoint),
}

impl fmt::Display for ArtifactStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { op, path, source } => {
                write!(f, "artifact store {op} {}: {source}", path.display())
            }
            Self::PathOverlap { left, right } => write!(
                f,
                "artifact/consensus path overlap: {} and {}",
                left.display(),
                right.display()
            ),
            Self::InvalidConfig(s) => write!(f, "invalid artifact store config: {s}"),
            Self::QuotaExceeded {
                used,
                requested,
                quota,
            } => write!(f, "artifact quota exceeded: {used}+{requested}>{quota}"),
            Self::InvalidShare(s) => write!(f, "invalid artifact share: {s}"),
            Self::NotFound => f.write_str("artifact share not found"),
            Self::NotPublished => f.write_str("artifact is not published"),
            Self::Corrupt { path, reason } => {
                write!(f, "artifact store corrupt {}: {reason}", path.display())
            }
            Self::Injected(p) => write!(f, "injected artifact failpoint: {p:?}"),
        }
    }
}
impl std::error::Error for ArtifactStoreError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactIngestSpec {
    pub artifact: ArtifactKey,
    pub stripe_count: u32,
    pub positions: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactResumeState {
    pub completed_stripes: BTreeSet<u32>,
    pub published: bool,
}

pub struct ArtifactStore {
    config: ArtifactStoreConfig,
    used_bytes: u64,
    failpoint: Option<ArtifactFailpoint>,
    ingests: BTreeMap<ArtifactKey, ArtifactIngestSpec>,
}

impl ArtifactStore {
    pub fn open(config: ArtifactStoreConfig) -> Result<Self, ArtifactStoreError> {
        validate_config(&config)?;
        for path in [
            &config.root,
            &config.segments,
            &config.wal,
            &config.index,
            &config.staging,
        ] {
            fs::create_dir_all(path).map_err(|e| io("create_dir_all", path, e))?;
        }
        let used_bytes = directory_bytes(&config.root)?;
        let mut store = Self {
            config,
            used_bytes,
            failpoint: None,
            ingests: BTreeMap::new(),
        };
        store.recover_wal()?;
        Ok(store)
    }

    #[must_use]
    pub fn config(&self) -> &ArtifactStoreConfig {
        &self.config
    }
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }
    pub fn set_failpoint(&mut self, point: Option<ArtifactFailpoint>) {
        self.failpoint = point;
    }

    pub fn begin_ingest(
        &mut self,
        mut spec: ArtifactIngestSpec,
    ) -> Result<ArtifactResumeState, ArtifactStoreError> {
        if spec.stripe_count == 0 || spec.positions.is_empty() || spec.positions.len() > 12 {
            return Err(ArtifactStoreError::InvalidConfig("ingest geometry"));
        }
        spec.positions.sort_unstable();
        spec.positions.dedup();
        if spec.positions.iter().any(|p| *p >= 12) {
            return Err(ArtifactStoreError::InvalidConfig("position outside 0..12"));
        }
        fs::create_dir_all(self.stage_dir(&spec.artifact)).map_err(|e| {
            io(
                "create staging artifact",
                &self.stage_dir(&spec.artifact),
                e,
            )
        })?;
        fs::create_dir_all(self.segment_dir(&spec.artifact)).map_err(|e| {
            io(
                "create segment artifact",
                &self.segment_dir(&spec.artifact),
                e,
            )
        })?;
        let state = self.resume_state(&spec.artifact)?;
        self.ingests.insert(spec.artifact, spec);
        Ok(state)
    }

    pub fn stage_share(
        &mut self,
        artifact: &ArtifactKey,
        stripe: u32,
        position: u8,
        bytes: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        let spec = self
            .ingests
            .get(artifact)
            .ok_or(ArtifactStoreError::InvalidConfig("begin_ingest required"))?;
        if stripe >= spec.stripe_count
            || spec.positions.binary_search(&position).is_err()
            || bytes.is_empty()
        {
            return Err(ArtifactStoreError::InvalidShare(
                "outside ingest specification",
            ));
        }
        let final_path = self.share_path(artifact, stripe, position);
        if final_path.exists() {
            return verify_existing(&final_path, bytes);
        }
        let path = self.stage_share_path(artifact, stripe, position);
        if path.exists() {
            return verify_existing(&path, bytes);
        }
        let framed = checked_bytes(bytes);
        self.reserve(framed.len() as u64)?;
        let temp = path.with_extension("part.tmp");
        let result = (|| {
            let mut file = File::create(&temp).map_err(|e| io("create staged share", &temp, e))?;
            file.write_all(&framed)
                .map_err(|e| io("write staged share", &temp, e))?;
            file.sync_all()
                .map_err(|e| io("sync staged share", &temp, e))?;
            fs::rename(&temp, &path).map_err(|e| io("rename staged share", &path, e))?;
            sync_dir(path.parent().expect("share parent"));
            Ok(())
        })();
        if result.is_err() {
            self.used_bytes = self.used_bytes.saturating_sub(framed.len() as u64);
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn checkpoint_stripe(
        &mut self,
        artifact: &ArtifactKey,
        stripe: u32,
    ) -> Result<(), ArtifactStoreError> {
        self.checkpoint_stripe_with_metadata(artifact, stripe, &[])
    }

    /// Persists the codec-owned canonical stripe/checkpoint row before
    /// acknowledging the stripe. ArtifactStore treats metadata as opaque;
    /// the codec revalidates it when resuming.
    pub fn checkpoint_stripe_with_metadata(
        &mut self,
        artifact: &ArtifactKey,
        stripe: u32,
        metadata: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        let spec = self
            .ingests
            .get(artifact)
            .ok_or(ArtifactStoreError::InvalidConfig("begin_ingest required"))?;
        if stripe >= spec.stripe_count {
            return Err(ArtifactStoreError::InvalidShare("checkpoint stripe"));
        }
        for position in &spec.positions {
            if !self.stage_share_path(artifact, stripe, *position).exists()
                && !self.share_path(artifact, stripe, *position).exists()
            {
                return Err(ArtifactStoreError::InvalidShare(
                    "checkpoint before every selected position is durable",
                ));
            }
        }
        let metadata_path = self.checkpoint_metadata_path(artifact, stripe);
        if metadata_path.exists() {
            verify_existing(&metadata_path, metadata)?;
        } else {
            let framed = checked_bytes(metadata);
            self.reserve(framed.len() as u64)?;
            let temp = metadata_path.with_extension("row.tmp");
            let result = (|| {
                let mut file =
                    File::create(&temp).map_err(|e| io("create checkpoint metadata", &temp, e))?;
                file.write_all(&framed)
                    .map_err(|e| io("write checkpoint metadata", &temp, e))?;
                file.sync_all()
                    .map_err(|e| io("sync checkpoint metadata", &temp, e))?;
                fs::rename(&temp, &metadata_path)
                    .map_err(|e| io("rename checkpoint metadata", &metadata_path, e))?;
                Ok(())
            })();
            if result.is_err() {
                self.used_bytes = self.used_bytes.saturating_sub(framed.len() as u64);
                let _ = fs::remove_file(&temp);
                return result;
            }
        }
        let state = self.resume_state(artifact)?;
        if state.completed_stripes.contains(&stripe) {
            return Ok(());
        }
        self.reserve(4)?;
        let path = self.checkpoint_path(artifact);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io("open checkpoint", &path, e))?;
        file.write_all(&stripe.to_le_bytes())
            .map_err(|e| io("append checkpoint", &path, e))?;
        file.sync_all()
            .map_err(|e| io("sync checkpoint", &path, e))?;
        Ok(())
    }

    pub fn publish(
        &mut self,
        artifact: &ArtifactKey,
        manifest: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        if self.index_path(artifact).exists() {
            self.verify_manifest(artifact, manifest)?;
            self.cleanup_staging(artifact)?;
            return Ok(());
        }
        let spec = self
            .ingests
            .get(artifact)
            .cloned()
            .ok_or(ArtifactStoreError::InvalidConfig("begin_ingest required"))?;
        let resume = self.resume_state(artifact)?;
        if resume.completed_stripes.len() != spec.stripe_count as usize {
            return Err(ArtifactStoreError::InvalidShare(
                "publish before all stripe checkpoints",
            ));
        }
        for stripe in 0..spec.stripe_count {
            for position in &spec.positions {
                let staged = self.stage_share_path(artifact, stripe, *position);
                let final_path = self.share_path(artifact, stripe, *position);
                if !final_path.exists() {
                    fs::rename(&staged, &final_path)
                        .map_err(|e| io("publish share rename", &final_path, e))?;
                }
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&final_path)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| io("sync published share", &final_path, e))?;
            }
        }
        sync_dir(&self.segment_dir(artifact));
        self.hit(ArtifactFailpoint::AfterSegmentSync)?;
        let record = encode_publish_record(&spec, manifest);
        self.append_wal(&record)?;
        self.hit(ArtifactFailpoint::AfterWalSync)?;
        self.write_index_atomic(artifact, &record)?;
        self.cleanup_staging(artifact)?;
        Ok(())
    }

    pub fn read_manifest(&self, artifact: &ArtifactKey) -> Result<Vec<u8>, ArtifactStoreError> {
        let record = read_checked(&self.index_path(artifact))?;
        let (_, manifest) = decode_publish_record(&record, &self.index_path(artifact))?;
        Ok(manifest)
    }

    pub fn read_share(
        &self,
        artifact: &ArtifactKey,
        stripe: u32,
        position: u8,
        out: &mut [u8],
    ) -> Result<(), ArtifactStoreError> {
        let bytes = self.read_share_bytes(artifact, stripe, position, out.len())?;
        out.copy_from_slice(&bytes);
        Ok(())
    }

    pub fn read_share_bytes(
        &self,
        artifact: &ArtifactKey,
        stripe: u32,
        position: u8,
        expected_len: usize,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        if !self.index_path(artifact).exists() {
            return Err(ArtifactStoreError::NotPublished);
        }
        let path = self.share_path(artifact, stripe, position);
        if !path.exists() {
            return Err(ArtifactStoreError::NotFound);
        }
        let bytes = read_checked(&path)?;
        if bytes.len() != expected_len {
            return Err(ArtifactStoreError::Corrupt {
                path,
                reason: "share length",
            });
        }
        Ok(bytes)
    }

    pub fn resume_state(
        &self,
        artifact: &ArtifactKey,
    ) -> Result<ArtifactResumeState, ArtifactStoreError> {
        let mut completed = BTreeSet::new();
        let path = self.checkpoint_path(artifact);
        if path.exists() {
            let bytes = fs::read(&path).map_err(|e| io("read checkpoint", &path, e))?;
            if bytes.len() % 4 != 0 {
                return Err(ArtifactStoreError::Corrupt {
                    path,
                    reason: "checkpoint length",
                });
            }
            for chunk in bytes.chunks_exact(4) {
                completed.insert(u32::from_le_bytes(chunk.try_into().expect("four")));
            }
        }
        Ok(ArtifactResumeState {
            completed_stripes: completed,
            published: self.index_path(artifact).exists(),
        })
    }

    pub fn resume_metadata(
        &self,
        artifact: &ArtifactKey,
    ) -> Result<Vec<(u32, Vec<u8>)>, ArtifactStoreError> {
        let state = self.resume_state(artifact)?;
        state
            .completed_stripes
            .into_iter()
            .map(|stripe| {
                let path = self.checkpoint_metadata_path(artifact, stripe);
                read_checked(&path).map(|metadata| (stripe, metadata))
            })
            .collect()
    }

    fn cleanup_staging(&mut self, artifact: &ArtifactKey) -> Result<(), ArtifactStoreError> {
        let stage = self.stage_dir(artifact);
        if !stage.exists() {
            return Ok(());
        }
        let staging_bytes = directory_bytes(&stage)?;
        fs::remove_dir_all(&stage).map_err(|error| io("remove artifact staging", &stage, error))?;
        sync_dir(&self.config.staging);
        self.used_bytes = self.used_bytes.saturating_sub(staging_bytes);
        Ok(())
    }

    fn verify_manifest(
        &self,
        artifact: &ArtifactKey,
        manifest: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        if self.read_manifest(artifact)? == manifest {
            Ok(())
        } else {
            Err(ArtifactStoreError::Corrupt {
                path: self.index_path(artifact),
                reason: "manifest mismatch",
            })
        }
    }
    fn reserve(&mut self, requested: u64) -> Result<(), ArtifactStoreError> {
        if self.used_bytes.saturating_add(requested) > self.config.quota_bytes {
            return Err(ArtifactStoreError::QuotaExceeded {
                used: self.used_bytes,
                requested,
                quota: self.config.quota_bytes,
            });
        }
        self.used_bytes += requested;
        Ok(())
    }
    fn hit(&mut self, point: ArtifactFailpoint) -> Result<(), ArtifactStoreError> {
        if self.failpoint == Some(point) {
            self.failpoint = None;
            Err(ArtifactStoreError::Injected(point))
        } else {
            Ok(())
        }
    }

    fn append_wal(&mut self, record: &[u8]) -> Result<(), ArtifactStoreError> {
        let path = self.config.wal.join("artifact.wal");
        let framed = checked_bytes(record);
        self.reserve(framed.len() as u64)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io("open artifact WAL", &path, e))?;
        f.write_all(&framed)
            .map_err(|e| io("append artifact WAL", &path, e))?;
        f.sync_all().map_err(|e| io("sync artifact WAL", &path, e))
    }

    fn write_index_atomic(
        &mut self,
        artifact: &ArtifactKey,
        record: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        let final_path = self.index_path(artifact);
        let temp = final_path.with_extension("idx.tmp");
        let bytes = checked_bytes(record);
        if !temp.exists() {
            self.reserve(bytes.len() as u64)?;
        }
        let mut f = File::create(&temp).map_err(|e| io("create artifact index", &temp, e))?;
        f.write_all(&bytes)
            .map_err(|e| io("write artifact index", &temp, e))?;
        f.sync_all()
            .map_err(|e| io("sync artifact index", &temp, e))?;
        self.hit(ArtifactFailpoint::BeforeIndexRename)?;
        fs::rename(&temp, &final_path).map_err(|e| io("rename artifact index", &final_path, e))?;
        sync_dir(&self.config.index);
        Ok(())
    }

    fn recover_wal(&mut self) -> Result<(), ArtifactStoreError> {
        let path = self.config.wal.join("artifact.wal");
        if !path.exists() {
            return Ok(());
        }
        let bytes = fs::read(&path).map_err(|e| io("read artifact WAL", &path, e))?;
        let mut at = 0_usize;
        while at < bytes.len() {
            if bytes.len() - at < 36 {
                break;
            }
            let len = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four")) as usize;
            if bytes.len() - at < 36 + len {
                break;
            }
            let frame = &bytes[at..at + 36 + len];
            let payload = decode_checked(frame, &path)?;
            let (spec, _) = decode_publish_record(&payload, &path)?;
            if shares_complete(self, &spec) && !self.index_path(&spec.artifact).exists() {
                self.write_index_atomic(&spec.artifact, &payload)?;
            }
            at += 36 + len;
        }
        Ok(())
    }

    fn stage_dir(&self, a: &ArtifactKey) -> PathBuf {
        self.config.staging.join(hex(a))
    }
    fn segment_dir(&self, a: &ArtifactKey) -> PathBuf {
        self.config.segments.join(hex(a))
    }
    fn stage_share_path(&self, a: &ArtifactKey, s: u32, p: u8) -> PathBuf {
        self.stage_dir(a).join(format!("{s:08}-{p:02}.share"))
    }
    fn share_path(&self, a: &ArtifactKey, s: u32, p: u8) -> PathBuf {
        self.segment_dir(a).join(format!("{s:08}-{p:02}.share"))
    }
    fn checkpoint_path(&self, a: &ArtifactKey) -> PathBuf {
        self.stage_dir(a).join("CHECKPOINT")
    }
    fn checkpoint_metadata_path(&self, a: &ArtifactKey, stripe: u32) -> PathBuf {
        self.stage_dir(a).join(format!("{stripe:08}.row"))
    }
    fn index_path(&self, a: &ArtifactKey) -> PathBuf {
        self.config.index.join(format!("{}.idx", hex(a)))
    }
}

fn validate_config(c: &ArtifactStoreConfig) -> Result<(), ArtifactStoreError> {
    if c.quota_bytes == 0
        || c.segment_size_bytes == 0
        || c.max_concurrency == 0
        || c.io_bytes_per_second == 0
    {
        return Err(ArtifactStoreError::InvalidConfig("zero capacity/limit"));
    }
    let root = absolute_normalized(&c.root)?;
    let consensus = absolute_normalized(&c.consensus_root)?;
    if overlaps(&root, &consensus) {
        return Err(ArtifactStoreError::PathOverlap {
            left: root,
            right: consensus,
        });
    }
    let children = [&c.segments, &c.wal, &c.index, &c.staging]
        .map(|p| absolute_normalized(p))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    for child in &children {
        if !child.starts_with(&root) || child == &root {
            return Err(ArtifactStoreError::InvalidConfig(
                "component path must be a strict child of artifact root",
            ));
        }
    }
    for i in 0..children.len() {
        for j in i + 1..children.len() {
            if overlaps(&children[i], &children[j]) {
                return Err(ArtifactStoreError::PathOverlap {
                    left: children[i].clone(),
                    right: children[j].clone(),
                });
            }
        }
    }
    Ok(())
}
fn absolute_normalized(path: &Path) -> Result<PathBuf, ArtifactStoreError> {
    let mut out = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().map_err(|e| io("current_dir", path, e))?
    };
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}
fn directory_bytes(path: &Path) -> Result<u64, ArtifactStoreError> {
    let mut total = 0_u64;
    if !path.exists() {
        return Ok(0);
    }
    for entry in fs::read_dir(path).map_err(|e| io("read_dir", path, e))? {
        let entry = entry.map_err(|e| io("read_dir entry", path, e))?;
        let meta = entry
            .metadata()
            .map_err(|e| io("metadata", &entry.path(), e))?;
        if meta.is_dir() {
            total = total.saturating_add(directory_bytes(&entry.path())?);
        } else {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
}
fn verify_existing(path: &Path, expected: &[u8]) -> Result<(), ArtifactStoreError> {
    let got = read_checked(path)?;
    if got == expected {
        Ok(())
    } else {
        Err(ArtifactStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "resume bytes differ",
        })
    }
}
fn sync_dir(path: &Path) {
    if let Ok(f) = File::open(path) {
        let _ = f.sync_all();
    }
}
fn io(op: &'static str, path: &Path, source: std::io::Error) -> ArtifactStoreError {
    ArtifactStoreError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}

fn encode_publish_record(spec: &ArtifactIngestSpec, manifest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(42 + spec.positions.len() + manifest.len());
    out.extend_from_slice(&spec.artifact);
    out.extend_from_slice(&spec.stripe_count.to_le_bytes());
    out.push(spec.positions.len() as u8);
    out.extend_from_slice(&spec.positions);
    out.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    out.extend_from_slice(manifest);
    out
}
fn decode_publish_record(
    bytes: &[u8],
    path: &Path,
) -> Result<(ArtifactIngestSpec, Vec<u8>), ArtifactStoreError> {
    if bytes.len() < 41 {
        return Err(ArtifactStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "short publish record",
        });
    }
    let mut artifact = [0_u8; 32];
    artifact.copy_from_slice(&bytes[..32]);
    let stripe_count = u32::from_le_bytes(bytes[32..36].try_into().expect("four"));
    let count = bytes[36] as usize;
    let at = 37 + count;
    if count == 0 || count > 12 || bytes.len() < at + 4 {
        return Err(ArtifactStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "position count",
        });
    }
    let positions = bytes[37..at].to_vec();
    let len = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four")) as usize;
    if bytes.len() != at + 4 + len {
        return Err(ArtifactStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "manifest length",
        });
    }
    Ok((
        ArtifactIngestSpec {
            artifact,
            stripe_count,
            positions,
        },
        bytes[at + 4..].to_vec(),
    ))
}
fn checked_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(blake3::hash(payload).as_bytes());
    out.extend_from_slice(payload);
    out
}
fn decode_checked(frame: &[u8], path: &Path) -> Result<Vec<u8>, ArtifactStoreError> {
    if frame.len() < 36 {
        return Err(ArtifactStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "short checked record",
        });
    }
    let len = u32::from_le_bytes(frame[..4].try_into().expect("four")) as usize;
    if frame.len() != 36 + len || blake3::hash(&frame[36..]).as_bytes() != &frame[4..36] {
        return Err(ArtifactStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "checked record digest/length",
        });
    }
    Ok(frame[36..].to_vec())
}
fn read_checked(path: &Path) -> Result<Vec<u8>, ArtifactStoreError> {
    if !path.exists() {
        return Err(ArtifactStoreError::NotPublished);
    }
    let bytes = fs::read(path).map_err(|e| io("read index", path, e))?;
    decode_checked(&bytes, path)
}
fn shares_complete(store: &ArtifactStore, spec: &ArtifactIngestSpec) -> bool {
    (0..spec.stripe_count).all(|s| {
        spec.positions
            .iter()
            .all(|p| store.share_path(&spec.artifact, s, *p).exists())
    })
}
