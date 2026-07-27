//! The store: open decision tree, WAL-backed atomic commits, snapshot
//! generations under the exact plan §7.3 law, retention, and pruning.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use noos_codec::{NoosDecode, NoosEncode};
use noos_lumen::state::{LumenRoots, StateDelta, TreeId};
use noos_lumen::Hash32;

use crate::blob::{BlobLoc, BlobStore};
use crate::engine::{
    Cf, Engine, META_IDENTITY, META_ROOTS, META_SAFETY_PREFIX, META_SCHEMA, SCHEMA_VERSION,
};
use crate::manifest::{CurrentPointerV1, FileEntryV1, ManifestV1, SegmentMarkV1, MAX_IDENTITY};
use crate::vfs::{join, Vfs};
use crate::wal::{self, OpV1, WalRecordV1, WalWriter};
use crate::{ctx_hash, FatalError, StoreConfig, StoreError, CTX_SAFETY, CTX_SAMPLE};

const CURRENT: &str = "CURRENT";
const CURRENT_TMP: &str = "CURRENT.tmp";
const LIVE_DIR: &str = "live";
const WAL_DIR: &str = "wal";
const SEGMENTS_DIR: &str = "segments";
const LOGS_DIR: &str = "engine-logs";
const MANIFEST_FILE: &str = "MANIFEST";
const PROVEN_FILE: &str = "PROVEN";
const ENGINE_SUBDIR: &str = "engine";

fn gen_dir_name(g: u64) -> String {
    format!("gen-{g:020}")
}

fn parse_gen_dir_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("gen-")?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn is_temp_dir_name(name: &str) -> bool {
    name.starts_with("tmp-")
}

// ---------------------------------------------------------------------------
// Public write-set types
// ---------------------------------------------------------------------------

/// A content-addressed blob destined for the append-only segments.
#[derive(Debug, Clone)]
pub struct Blob {
    pub hash: Hash32,
    pub bytes: Vec<u8>,
}

/// One atomic commit: Lumen delta + caller-keyed sections + blobs.
#[derive(Debug, Clone, Default)]
pub struct WriteSet {
    /// Canonical ordered delta from `noos-lumen` (applied to the `state` CF).
    pub delta: StateDelta,
    /// Post-commit six Lumen roots (stored in metadata when present).
    pub roots: Option<LumenRoots>,
    pub headers: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    pub indices: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    pub receipts: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    pub blobs: Vec<Blob>,
}

/// Fallback taken during open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackInfo {
    pub pointed: u64,
    pub pointed_reason: String,
    pub adopted: u64,
}

/// What `Store::open` observed and did.
#[derive(Debug, Clone, Default)]
pub struct OpenReport {
    pub initialized: bool,
    pub fell_back: Option<FallbackInfo>,
    pub wal_truncated_bytes: u64,
    pub replayed_records: u64,
    pub live_rebuilt: bool,
    pub proved_generation: Option<u64>,
}

/// What `Store::prune` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub removed_generations: Vec<u64>,
    pub removed_wal_segments: Vec<u64>,
    pub removed_temp_dirs: u64,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Owned `(key, value)` entry returned by [`Store::scan`].
pub type ScanEntry = (Vec<u8>, Vec<u8>);

/// Durable store handle. Single-writer: `&mut self` on every mutation.
pub struct Store {
    cfg: StoreConfig,
    vfs: Arc<dyn Vfs>,
    engine: Engine,
    wal: WalWriter,
    blobs: BlobStore,
    applied_seq: u64,
    current_gen: u64,
    poisoned: bool,
    report: OpenReport,
}

impl Store {
    // -- paths ---------------------------------------------------------------

    fn p_current(root: &Path) -> PathBuf {
        join(root, CURRENT)
    }
    fn p_current_tmp(root: &Path) -> PathBuf {
        join(root, CURRENT_TMP)
    }
    fn p_live(root: &Path) -> PathBuf {
        join(root, LIVE_DIR)
    }
    fn p_wal(root: &Path) -> PathBuf {
        join(root, WAL_DIR)
    }
    fn p_segments(root: &Path) -> PathBuf {
        join(root, SEGMENTS_DIR)
    }
    fn p_logs(root: &Path) -> PathBuf {
        join(root, LOGS_DIR)
    }
    fn p_gen(root: &Path, g: u64) -> PathBuf {
        join(root, &gen_dir_name(g))
    }

    // -- open ------------------------------------------------------------------

    /// Open (or initialize) the store. Implements the plan §7.3 startup
    /// decision tree; see `protocol/schemas/store-v1.md` §7.
    pub fn open(cfg: StoreConfig, vfs: Arc<dyn Vfs>) -> Result<Store, StoreError> {
        if cfg.identity.is_empty() || cfg.identity.len() > MAX_IDENTITY as usize {
            return Err(StoreError::InvalidWriteSet(
                "identity must be 1..=128 bytes",
            ));
        }
        let root = cfg.root.clone();
        let gens = list_generations(&vfs, &root)?;
        let has_current = vfs.exists(&Self::p_current(&root));

        if gens.is_empty() && !has_current {
            // Empty root (orphan temp dirs / partial init scaffolding are
            // ignored — nothing durable exists yet).
            if !cfg.create_if_missing {
                return Err(StoreError::NotInitialized);
            }
            return Self::init(cfg, vfs);
        }

        if !has_current {
            // Generations exist without a pointer. The ONLY recoverable
            // shape is the interrupted-first-init signature: exactly
            // generation 1, no PROVEN marker anywhere, and an empty WAL.
            // Everything else is a missing pointer on an established
            // store: fatal, never auto-adopted.
            let scan_probe = wal::scan(&vfs, &Self::p_wal(&root), false)?;
            let any_proven = gens
                .iter()
                .any(|g| vfs.exists(&join(&Self::p_gen(&root, *g), PROVEN_FILE)));
            if gens == vec![1] && scan_probe.records.is_empty() && !any_proven {
                let gen_dir = Self::p_gen(&root, 1);
                let manifest =
                    match validate_generation(&vfs, &gen_dir, 1, None, &cfg.identity, false)? {
                        Ok(m) => m,
                        Err(reason) => {
                            return Err(StoreError::Fatal(FatalError::NoValidGeneration {
                                pointed: 1,
                                pointed_reason: reason,
                                fallback_reason: None,
                            }))
                        }
                    };
                flip_current(&vfs, &root, 1, manifest.hash())?;
                // Fall through to the normal path below.
            } else {
                return Err(StoreError::Fatal(FatalError::PointerMissing));
            }
        }

        // Parse the pointer (checksummed).
        let ptr_path = Self::p_current(&root);
        let ptr_bytes = vfs
            .read(&ptr_path)
            .map_err(|e| StoreError::io("read", &ptr_path, e))?;
        let ptr = CurrentPointerV1::from_file_bytes(&ptr_bytes)
            .map_err(|reason| StoreError::Fatal(FatalError::PointerCorrupt { reason }))?;

        // Validate the pointed generation.
        let pointed_dir = Self::p_gen(&root, ptr.generation);
        let pointed = if vfs.is_dir(&pointed_dir) {
            validate_generation(
                &vfs,
                &pointed_dir,
                ptr.generation,
                Some(ptr.manifest_hash),
                &cfg.identity,
                true,
            )?
        } else {
            Err("generation directory missing".to_string())
        };

        let mut report = OpenReport::default();
        let (base_gen, base_manifest) = match pointed {
            Ok(m) => (ptr.generation, m),
            Err(pointed_reason) => {
                // Fallback: highest retained previously verified generation.
                let mut chosen: Option<(u64, ManifestV1)> = None;
                let mut fallback_reason: Option<String> = None;
                for g in gens.iter().rev().filter(|g| **g < ptr.generation) {
                    let dir = Self::p_gen(&root, *g);
                    match validate_generation(&vfs, &dir, *g, None, &cfg.identity, false)? {
                        Ok(m) => {
                            chosen = Some((*g, m));
                            break;
                        }
                        Err(r) => {
                            if fallback_reason.is_none() {
                                fallback_reason = Some(r);
                            }
                        }
                    }
                }
                match chosen {
                    Some((g, m)) => {
                        report.fell_back = Some(FallbackInfo {
                            pointed: ptr.generation,
                            pointed_reason,
                            adopted: g,
                        });
                        (g, m)
                    }
                    None => {
                        return Err(StoreError::Fatal(FatalError::NoValidGeneration {
                            pointed: ptr.generation,
                            pointed_reason,
                            fallback_reason,
                        }))
                    }
                }
            }
        };

        // Scan the protocol WAL, applying the final-record EOF rule.
        let scan = wal::scan(&vfs, &Self::p_wal(&root), true)?;
        report.wal_truncated_bytes = scan.truncated_bytes;
        let wal_last = scan.last_seq;
        if base_manifest.applied_seq > wal_last {
            return Err(StoreError::Fatal(FatalError::HistoryGap {
                detail: format!(
                    "generation {} reflects seq {} but retained WAL ends at {}",
                    base_gen, base_manifest.applied_seq, wal_last
                ),
            }));
        }

        // Choose the base engine: the live engine when the WAL joins it,
        // else a rebuild from the base generation (snapshot+tail replay).
        let live_dir = Self::p_live(&root);
        let logs_dir = Self::p_logs(&root);
        vfs.create_dir_all(&logs_dir)
            .map_err(|e| StoreError::io("create_dir_all", &logs_dir, e))?;
        let mut live: Option<Engine> = if vfs.is_dir(&live_dir) {
            fail_at(&vfs, "live_open")?;
            Engine::open(&live_dir, &logs_dir, false).ok()
        } else {
            None
        };
        let mut usable = false;
        if let Some(eng) = live.as_ref() {
            match (eng.identity()?, eng.schema_version()?) {
                (Some(id), Some(SCHEMA_VERSION)) => {
                    if id != cfg.identity {
                        return Err(StoreError::Fatal(FatalError::IdentityMismatch));
                    }
                    let a = eng.applied_seq()?;
                    if a > wal_last {
                        return Err(StoreError::Fatal(FatalError::HistoryGap {
                            detail: format!(
                                "live engine at seq {a} is ahead of durable WAL end {wal_last}"
                            ),
                        }));
                    }
                    // Replayable when the tail (a, wal_last] is present.
                    usable = a == wal_last
                        || scan
                            .first_seq
                            .is_some_and(|f| a.checked_add(1).is_some_and(|next| f <= next));
                }
                // Half-built or pre-identity live engine: rebuildable cache.
                _ => usable = false,
            }
        }
        let engine = if usable {
            match live.take() {
                Some(e) => e,
                None => return Err(StoreError::Engine("live engine vanished".to_string())),
            }
        } else {
            drop(live);
            report.live_rebuilt = true;
            rebuild_live(&vfs, &root, base_gen, &base_manifest)?;
            fail_at(&vfs, "live_open_rebuilt")?;
            let eng = Engine::open(&live_dir, &logs_dir, false)?;
            let a = eng.applied_seq()?;
            if a != base_manifest.applied_seq {
                return Err(StoreError::Fatal(FatalError::ReplayDivergence {
                    detail: format!(
                        "rebuilt engine reports seq {a}, manifest says {}",
                        base_manifest.applied_seq
                    ),
                }));
            }
            // The tail (a, wal_last] must be present.
            if wal_last > a {
                let next = a
                    .checked_add(1)
                    .ok_or(StoreError::Arithmetic("seq successor"))?;
                if scan.first_seq.is_none_or(|f| f > next) {
                    return Err(StoreError::Fatal(FatalError::HistoryGap {
                        detail: format!(
                            "rebuild needs WAL from seq {next} but retained WAL starts at {:?}",
                            scan.first_seq
                        ),
                    }));
                }
            }
            eng
        };

        // Replay the tail. Records are globally contiguous (scan enforced).
        let a0 = engine.applied_seq()?;
        let mut expected = a0
            .checked_add(1)
            .ok_or(StoreError::Arithmetic("seq successor"))?;
        for rec in scan.records.iter().filter(|r| r.seq > a0) {
            if rec.seq != expected {
                return Err(StoreError::Fatal(FatalError::HistoryGap {
                    detail: format!("replay expected seq {expected}, found {}", rec.seq),
                }));
            }
            fail_at(&vfs, "engine_apply_replay")?;
            engine.apply(&rec.ops, rec.seq)?;
            expected = rec
                .seq
                .checked_add(1)
                .ok_or(StoreError::Arithmetic("seq successor"))?;
            report.replayed_records = report
                .replayed_records
                .checked_add(1)
                .ok_or(StoreError::Arithmetic("replay count"))?;
        }
        let applied_seq = engine.applied_seq()?;

        // Fresh-process proof of snapshot+tail replay (retention gate).
        let base_dir = Self::p_gen(&root, base_gen);
        let proven_path = join(&base_dir, PROVEN_FILE);
        if cfg.prove_replay_on_open && !vfs.exists(&proven_path) {
            prove_replay(&vfs, &cfg, &root, base_gen, &base_manifest, &scan, &engine)?;
            report.proved_generation = Some(base_gen);
        }

        // A fallback becomes the durable pointer only after it fully
        // opened and replayed.
        if let Some(fb) = report.fell_back.as_ref() {
            flip_current(&vfs, &root, fb.adopted, base_manifest.hash())?;
        }

        let wal_writer = WalWriter::open(
            Arc::clone(&vfs),
            Self::p_wal(&root),
            cfg.wal_segment_bytes,
            scan.segments.last().copied(),
        )?;
        vfs.create_dir_all(&Self::p_segments(&root))
            .map_err(|e| StoreError::io("create_dir_all", &Self::p_segments(&root), e))?;
        let blobs = BlobStore::open(
            Arc::clone(&vfs),
            Self::p_segments(&root),
            cfg.blob_segment_bytes,
        )?;

        Ok(Store {
            cfg,
            vfs,
            engine,
            wal: wal_writer,
            blobs,
            applied_seq,
            current_gen: base_gen,
            poisoned: false,
            report,
        })
    }

    /// First-time initialization: live engine, then verified generation 1,
    /// then the pointer — in that order, so every crash prefix is either
    /// "empty store" or the roll-forward signature.
    fn init(cfg: StoreConfig, vfs: Arc<dyn Vfs>) -> Result<Store, StoreError> {
        let root = cfg.root.clone();
        for dir in [
            root.clone(),
            Self::p_wal(&root),
            Self::p_segments(&root),
            Self::p_logs(&root),
        ] {
            vfs.create_dir_all(&dir)
                .map_err(|e| StoreError::io("create_dir_all", &dir, e))?;
        }
        let live_dir = Self::p_live(&root);
        // Init is only reachable when NO durable history exists (no
        // generations, no pointer): a leftover half-created live engine
        // from an interrupted earlier init carries nothing and must not
        // wedge re-initialization.
        if vfs.is_dir(&live_dir) {
            vfs.remove_dir_all(&live_dir)
                .map_err(|e| StoreError::io("remove_dir_all", &live_dir, e))?;
        }
        fail_at(&vfs, "engine_create")?;
        let engine = Engine::open(&live_dir, &Self::p_logs(&root), true)?;
        let init_ops = vec![
            OpV1 {
                cf: Cf::Meta,
                key: META_IDENTITY.to_vec(),
                value: Some(cfg.identity.clone()),
            },
            OpV1 {
                cf: Cf::Meta,
                key: META_SCHEMA.to_vec(),
                value: Some(SCHEMA_VERSION.to_le_bytes().to_vec()),
            },
            OpV1 {
                cf: Cf::Meta,
                key: META_ROOTS.to_vec(),
                value: Some(vec![0u8; 192]),
            },
        ];
        fail_at(&vfs, "engine_apply_init")?;
        engine.apply(&init_ops, 0)?;

        let wal_writer = WalWriter::open(
            Arc::clone(&vfs),
            Self::p_wal(&root),
            cfg.wal_segment_bytes,
            None,
        )?;
        let blobs = BlobStore::open(
            Arc::clone(&vfs),
            Self::p_segments(&root),
            cfg.blob_segment_bytes,
        )?;
        let mut store = Store {
            cfg,
            vfs,
            engine,
            wal: wal_writer,
            blobs,
            applied_seq: 0,
            current_gen: 0,
            poisoned: false,
            report: OpenReport {
                initialized: true,
                ..OpenReport::default()
            },
        };
        let manifest_hash = store.snapshot_core(1)?;
        flip_current(&store.vfs, &store.cfg.root, 1, manifest_hash)?;
        store.current_gen = 1;
        // Generation 1 is trivially proven: it has no tail and was just
        // verified by this fresh process.
        write_proven(&store.vfs, &Self::p_gen(&store.cfg.root, 1), manifest_hash)?;
        store.report.proved_generation = Some(1);
        Ok(store)
    }

    // -- accessors -------------------------------------------------------------

    pub fn open_report(&self) -> &OpenReport {
        &self.report
    }

    pub fn applied_seq(&self) -> u64 {
        self.applied_seq
    }

    pub fn current_generation(&self) -> u64 {
        self.current_gen
    }

    /// The six Lumen roots recorded by the last commit that carried them.
    pub fn roots(&self) -> Result<Option<LumenRoots>, StoreError> {
        match self.engine.roots_bytes()? {
            None => Ok(None),
            Some(v) => Ok(Some(decode_roots(&v)?)),
        }
    }

    pub fn get_state(
        &self,
        tree: TreeId,
        key: &Hash32,
        sub_key: Option<&Hash32>,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.engine.get(Cf::State, &state_key(tree, key, sub_key))
    }

    pub fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.engine.get(Cf::Headers, key)
    }

    pub fn get_index(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.engine.get(Cf::Indices, key)
    }

    pub fn get_receipt(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.engine.get(Cf::Receipts, key)
    }

    /// Fetch + verify a blob by content hash.
    pub fn get_blob(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, StoreError> {
        match self.engine.get(Cf::BlobIndex, hash)? {
            None => Ok(None),
            Some(v) => {
                let loc = BlobLoc::decode_canonical(&v)?;
                Ok(Some(self.blobs.read(&loc, hash)?))
            }
        }
    }

    /// All persisted safety-record payloads of `kind` (ascending by
    /// payload hash).
    pub fn safety_records(&self, kind: u16) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut prefix = META_SAFETY_PREFIX.to_vec();
        prefix.extend_from_slice(&kind.to_le_bytes());
        Ok(self
            .engine
            .prefix_scan(Cf::Meta, &prefix)?
            .into_iter()
            .map(|(_, v)| v)
            .collect())
    }

    /// Read-only ascending prefix scan over a section column family
    /// (headers / indices / receipts). Additive node-runtime API: the
    /// node's restart replay enumerates its height index and certificate
    /// log through this; nothing here mutates state.
    pub fn scan(&self, cf: Cf, prefix: &[u8]) -> Result<Vec<ScanEntry>, StoreError> {
        self.engine.prefix_scan(cf, prefix)
    }

    // -- writes ----------------------------------------------------------------

    fn ensure_live(&self) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        Ok(())
    }

    /// Commit one write set atomically through the protocol WAL:
    /// blob-append+fsync → WAL append+fsync → engine apply (which marks
    /// `applied_seq` in the same batch). Ok ⇒ crash-durable.
    pub fn commit(&mut self, ws: WriteSet) -> Result<u64, StoreError> {
        self.ensure_live()?;
        match self.commit_inner(ws) {
            Ok(seq) => Ok(seq),
            Err(error) => {
                // A rejected write set touches no referenced durable state
                // (at worst it appended unreferenced blob bytes); only a
                // failure past validation leaves this handle ambiguous.
                if !matches!(error, StoreError::InvalidWriteSet(_)) {
                    self.poisoned = true;
                }
                Err(error)
            }
        }
    }

    fn commit_inner(&mut self, ws: WriteSet) -> Result<u64, StoreError> {
        let profile = std::env::var_os("NOOS_THROUGHPUT_PROFILE").is_some();
        let operation_started = Instant::now();
        let WriteSet {
            delta,
            roots,
            headers,
            indices,
            receipts,
            mut blobs,
        } = ws;
        let op_capacity = delta
            .entries
            .len()
            .saturating_add(headers.len())
            .saturating_add(indices.len())
            .saturating_add(receipts.len())
            .saturating_add(blobs.len())
            .saturating_add(usize::from(roots.is_some()));
        let mut ops: Vec<OpV1> = Vec::with_capacity(op_capacity);

        // State deltas are already canonically ordered by the transition.
        for entry in delta.entries {
            let key = state_key(entry.tree, &entry.key, entry.sub_key.as_ref());
            if ops
                .last()
                .is_some_and(|previous| previous.key.as_slice() >= key.as_slice())
            {
                return Err(StoreError::InvalidWriteSet(
                    "state delta not canonically ordered",
                ));
            }
            ops.push(OpV1 {
                cf: Cf::State,
                key,
                value: entry.value,
            });
        }

        // Caller-keyed sections are sorted in place. Ownership avoids cloning
        // every receipt and index value into the WAL operation vector.
        for (cf, mut section) in [
            (Cf::Headers, headers),
            (Cf::Indices, indices),
            (Cf::Receipts, receipts),
        ] {
            if section
                .iter()
                .any(|(key, _)| key.is_empty() || key.len() > wal::MAX_KEY as usize)
            {
                return Err(StoreError::InvalidWriteSet(
                    "section key size out of bounds",
                ));
            }
            section.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            if section.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(StoreError::InvalidWriteSet("duplicate section key"));
            }
            ops.extend(
                section
                    .into_iter()
                    .map(|(key, value)| OpV1 { cf, key, value }),
            );
        }
        if profile {
            eprintln!(
                "NOOS_PROFILE store_operation_build_seconds={:.9}",
                operation_started.elapsed().as_secs_f64()
            );
        }
        let blob_started = Instant::now();

        // Validate and order blobs before any IO. Bytes are appended and
        // fsynced before the WAL record can reference their locations.
        blobs.sort_unstable_by_key(|blob| blob.hash);
        if blobs.windows(2).any(|pair| pair[0].hash == pair[1].hash) {
            return Err(StoreError::InvalidWriteSet("duplicate blob hash"));
        }
        if blobs
            .iter()
            .any(|blob| blob.bytes.len() > self.cfg.max_blob_bytes as usize)
        {
            return Err(StoreError::InvalidWriteSet("blob exceeds max_blob_bytes"));
        }
        for blob in &blobs {
            let location = self.blobs.append(&blob.hash, &blob.bytes)?;
            ops.push(OpV1 {
                cf: Cf::BlobIndex,
                key: blob.hash.to_vec(),
                value: Some(location.encode_canonical()),
            });
        }
        if !blobs.is_empty() {
            self.blobs.fsync_active()?;
        }
        if profile {
            eprintln!(
                "NOOS_PROFILE store_blob_commit_seconds={:.9}",
                blob_started.elapsed().as_secs_f64()
            );
        }

        if let Some(roots) = roots {
            ops.push(OpV1 {
                cf: Cf::Meta,
                key: META_ROOTS.to_vec(),
                value: Some(encode_roots(&roots)),
            });
        }
        if ops.is_empty() {
            return Err(StoreError::InvalidWriteSet("empty write set"));
        }
        self.commit_ops(ops)
    }

    /// WAL record → fsync → engine apply → mark applied.
    fn commit_ops(&mut self, ops: Vec<OpV1>) -> Result<u64, StoreError> {
        if ops.len() > wal::MAX_OPS as usize {
            return Err(StoreError::InvalidWriteSet("write set exceeds MAX_OPS"));
        }
        let seq = self
            .applied_seq
            .checked_add(1)
            .ok_or(StoreError::Arithmetic("seq successor"))?;
        let record = WalRecordV1 { seq, ops };
        let profile = std::env::var_os("NOOS_THROUGHPUT_PROFILE").is_some();
        let wal_started = Instant::now();
        self.wal.append(&record)?;
        if profile {
            eprintln!(
                "NOOS_PROFILE store_wal_commit_seconds={:.9}",
                wal_started.elapsed().as_secs_f64()
            );
        }
        let engine_started = Instant::now();
        fail_at(&self.vfs, "engine_apply")?;
        self.engine.apply(&record.ops, seq)?;
        if profile {
            eprintln!(
                "NOOS_PROFILE store_engine_commit_seconds={:.9}",
                engine_started.elapsed().as_secs_f64()
            );
        }
        self.applied_seq = seq;
        Ok(seq)
    }

    /// Persist-before-vote safety record (consumed by the `noos-witness`
    /// `DurabilityBarrier` adapter at the composition layer). Returns only
    /// after the record is fsynced into the protocol WAL; recovery replays
    /// it into the metadata CF.
    pub fn persist_safety_record(&mut self, kind: u16, payload: &[u8]) -> Result<u64, StoreError> {
        self.ensure_live()?;
        if payload.is_empty() || payload.len() > wal::MAX_VALUE as usize {
            return Err(StoreError::InvalidWriteSet(
                "safety payload size out of bounds",
            ));
        }
        let mut key = META_SAFETY_PREFIX.to_vec();
        key.extend_from_slice(&kind.to_le_bytes());
        key.extend_from_slice(&ctx_hash(CTX_SAFETY, payload));
        let ops = vec![OpV1 {
            cf: Cf::Meta,
            key,
            value: Some(payload.to_vec()),
        }];
        match self.commit_ops(ops) {
            Ok(seq) => Ok(seq),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    /// Durability barrier: everything previously acked is durable when this
    /// returns Ok (defensive fsync of WAL + active blob segment).
    pub fn barrier(&mut self) -> Result<(), StoreError> {
        self.ensure_live()?;
        match self.wal.fsync().and_then(|()| self.blobs.fsync_active()) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    // -- snapshots ---------------------------------------------------------------

    /// Create, verify, and adopt snapshot generation `max+1` under the
    /// exact §7.3 law. Returns the new generation number.
    pub fn create_snapshot(&mut self) -> Result<u64, StoreError> {
        self.ensure_live()?;
        match self.create_snapshot_inner() {
            Ok(g) => Ok(g),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn create_snapshot_inner(&mut self) -> Result<u64, StoreError> {
        let gens = list_generations(&self.vfs, &self.cfg.root)?;
        let next = gens
            .last()
            .copied()
            .unwrap_or(0)
            .max(self.current_gen)
            .checked_add(1)
            .ok_or(StoreError::Arithmetic("generation successor"))?;
        let manifest_hash = self.snapshot_core(next)?;
        flip_current(&self.vfs, &self.cfg.root, next, manifest_hash)?;
        self.current_gen = next;
        Ok(next)
    }

    /// Snapshot body: temp dir → checkpoint → fsync everything → manifest
    /// → verify (roots + proof samples) → atomic rename. Returns the
    /// manifest hash; the caller flips `CURRENT`.
    fn snapshot_core(&mut self, gen: u64) -> Result<[u8; 32], StoreError> {
        let root = self.cfg.root.clone();
        let tmp = join(
            &root,
            &format!("tmp-gen-{gen:020}-{:020}", self.applied_seq),
        );
        if self.vfs.exists(&tmp) {
            self.vfs
                .remove_dir_all(&tmp)
                .map_err(|e| StoreError::io("remove_dir_all", &tmp, e))?;
        }
        self.vfs
            .create_dir_all(&tmp)
            .map_err(|e| StoreError::io("create_dir_all", &tmp, e))?;
        let tmp_engine = join(&tmp, ENGINE_SUBDIR);
        fail_at(&self.vfs, "engine_checkpoint")?;
        self.engine.checkpoint(&tmp_engine)?;

        // fsync + hash every checkpoint file.
        let rels = walk_files(&self.vfs, &tmp, ENGINE_SUBDIR)?;
        let mut engine_files = Vec::with_capacity(rels.len());
        for rel in rels {
            let p = join(&tmp, &rel);
            self.vfs
                .fsync_path(&p)
                .map_err(|e| StoreError::io("fsync", &p, e))?;
            let bytes = self
                .vfs
                .read(&p)
                .map_err(|e| StoreError::io("read", &p, e))?;
            engine_files.push(FileEntryV1 {
                rel_path: rel,
                size: bytes.len() as u64,
                hash: ctx_hash(crate::CTX_FILE, &bytes),
            });
        }

        // Blob-segment watermarks (fsyncs the active segment).
        let mut segments = Vec::new();
        for (segment, len) in self.blobs.watermarks()? {
            let prefix_hash =
                BlobStore::prefix_hash(&self.vfs, &Self::p_segments(&root), segment, len)?;
            segments.push(SegmentMarkV1 {
                segment,
                len,
                prefix_hash,
            });
        }

        let roots = match self.engine.roots_bytes()? {
            Some(v) => roots_array(&v)?,
            None => [[0u8; 32]; 6],
        };
        let manifest = ManifestV1 {
            generation: gen,
            applied_seq: self.applied_seq,
            identity: self.cfg.identity.clone(),
            roots,
            engine_files,
            segments,
        };
        let manifest_file_bytes = manifest.to_file_bytes();
        let manifest_path = join(&tmp, MANIFEST_FILE);
        self.vfs
            .write_file(&manifest_path, &manifest_file_bytes)
            .map_err(|e| StoreError::io("write", &manifest_path, e))?;
        self.vfs
            .fsync_path(&manifest_path)
            .map_err(|e| StoreError::io("fsync", &manifest_path, e))?;
        self.vfs
            .sync_dir(&tmp_engine)
            .map_err(|e| StoreError::io("sync_dir", &tmp_engine, e))?;
        self.vfs
            .sync_dir(&tmp)
            .map_err(|e| StoreError::io("sync_dir", &tmp, e))?;

        // Verify roots and proof samples against the live engine before
        // the generation may exist under its final name.
        fail_at(&self.vfs, "verify_open")?;
        {
            let ro = Engine::open_read_only(&tmp_engine, &Self::p_logs(&root))?;
            verify_engines_equal(&self.cfg, gen, &ro, &self.engine, self.applied_seq)
                .map_err(StoreError::SnapshotVerifyFailed)?;
        }

        // Atomic adoption: rename + parent flush.
        let final_dir = Self::p_gen(&root, gen);
        self.vfs
            .rename(&tmp, &final_dir)
            .map_err(|e| StoreError::io("rename", &final_dir, e))?;
        self.vfs
            .sync_dir(&root)
            .map_err(|e| StoreError::io("sync_dir", &root, e))?;
        Ok(manifest.hash())
    }

    // -- retention ---------------------------------------------------------------

    /// Prune under the retention law: keep the current generation, its
    /// predecessor, and everything not yet covered by a fresh-process
    /// replay proof; keep every WAL segment needed by a retained
    /// generation; never delete the last verified generation. Also removes
    /// orphan temp directories.
    pub fn prune(&mut self) -> Result<PruneReport, StoreError> {
        self.ensure_live()?;
        match self.prune_inner() {
            Ok(r) => Ok(r),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn prune_inner(&mut self) -> Result<PruneReport, StoreError> {
        let root = self.cfg.root.clone();
        let mut report = PruneReport::default();
        let gens = list_generations(&self.vfs, &root)?;
        let prev = gens.iter().rev().find(|g| **g < self.current_gen).copied();
        let proven_max = gens
            .iter()
            .rev()
            .find(|g| {
                self.vfs
                    .exists(&join(&Self::p_gen(&root, **g), PROVEN_FILE))
            })
            .copied();

        let mut kept: Vec<u64> = Vec::new();
        for g in &gens {
            let removable =
                *g != self.current_gen && Some(*g) != prev && proven_max.is_some_and(|p| *g < p);
            if removable {
                let dir = Self::p_gen(&root, *g);
                self.vfs
                    .remove_dir_all(&dir)
                    .map_err(|e| StoreError::io("remove_dir_all", &dir, e))?;
                report.removed_generations.push(*g);
            } else {
                kept.push(*g);
            }
        }

        // Orphan temp directories.
        for name in self
            .vfs
            .read_dir(&root)
            .map_err(|e| StoreError::io("read_dir", &root, e))?
        {
            if is_temp_dir_name(&name) {
                let p = join(&root, &name);
                if self.vfs.is_dir(&p) {
                    self.vfs
                        .remove_dir_all(&p)
                        .map_err(|e| StoreError::io("remove_dir_all", &p, e))?;
                    report.removed_temp_dirs = report
                        .removed_temp_dirs
                        .checked_add(1)
                        .ok_or(StoreError::Arithmetic("temp dir count"))?;
                }
            }
        }

        // WAL retention floor: the smallest applied_seq any retained
        // generation reflects. Unreadable manifests keep everything.
        let mut floor = self.applied_seq;
        for g in &kept {
            let mpath = join(&Self::p_gen(&root, *g), MANIFEST_FILE);
            let applied = self
                .vfs
                .read(&mpath)
                .ok()
                .and_then(|b| ManifestV1::from_file_bytes(&b).ok())
                .map(|(m, _)| m.applied_seq);
            match applied {
                Some(a) => floor = floor.min(a),
                None => floor = 0,
            }
        }
        // Remove whole segments strictly below the floor; never the newest.
        let wal_dir = Self::p_wal(&root);
        let scan_segments = {
            let mut segs: Vec<u64> = Vec::new();
            for name in self
                .vfs
                .read_dir(&wal_dir)
                .map_err(|e| StoreError::io("read_dir", &wal_dir, e))?
            {
                if let Some(first) = wal::parse_segment_name(&name) {
                    segs.push(first);
                }
            }
            segs.sort_unstable();
            segs
        };
        for pair in scan_segments.windows(2) {
            let (first, next_first) = (pair[0], pair[1]);
            let max_seq = next_first
                .checked_sub(1)
                .ok_or(StoreError::Arithmetic("segment max seq"))?;
            if max_seq <= floor {
                let p = join(&wal_dir, &wal::segment_name(first));
                self.vfs
                    .remove_file(&p)
                    .map_err(|e| StoreError::io("remove_file", &p, e))?;
                report.removed_wal_segments.push(first);
            }
        }
        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Explicit crash boundary for engine-side operations that bypass the Vfs.
fn fail_at(vfs: &Arc<dyn Vfs>, label: &'static str) -> Result<(), StoreError> {
    vfs.failpoint(label).map_err(|e| StoreError::Io {
        op: label,
        path: String::new(),
        source: e,
    })
}

pub(crate) fn state_key(tree: TreeId, key: &Hash32, sub_key: Option<&Hash32>) -> Vec<u8> {
    let mut out = Vec::with_capacity(66);
    out.push(tree as u8);
    out.extend_from_slice(key);
    match sub_key {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            out.extend_from_slice(s);
        }
    }
    out
}

fn encode_roots(r: &LumenRoots) -> Vec<u8> {
    let mut out = Vec::with_capacity(192);
    for part in [
        &r.notes_root,
        &r.nullifiers_root,
        &r.accounts_root,
        &r.objects_root,
        &r.receipts_root,
        &r.params_root,
    ] {
        out.extend_from_slice(part);
    }
    out
}

fn roots_array(v: &[u8]) -> Result<[[u8; 32]; 6], StoreError> {
    if v.len() != 192 {
        return Err(StoreError::Engine("malformed lumen_roots".to_string()));
    }
    let mut out = [[0u8; 32]; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = i
            .checked_mul(32)
            .ok_or(StoreError::Arithmetic("roots offset"))?;
        let end = start
            .checked_add(32)
            .ok_or(StoreError::Arithmetic("roots offset"))?;
        slot.copy_from_slice(&v[start..end]);
    }
    Ok(out)
}

fn decode_roots(v: &[u8]) -> Result<LumenRoots, StoreError> {
    let a = roots_array(v)?;
    Ok(LumenRoots {
        notes_root: a[0],
        nullifiers_root: a[1],
        accounts_root: a[2],
        objects_root: a[3],
        receipts_root: a[4],
        params_root: a[5],
    })
}

fn list_generations(vfs: &Arc<dyn Vfs>, root: &Path) -> Result<Vec<u64>, StoreError> {
    let mut out = Vec::new();
    if !vfs.is_dir(root) {
        return Ok(out);
    }
    for name in vfs
        .read_dir(root)
        .map_err(|e| StoreError::io("read_dir", root, e))?
    {
        if let Some(g) = parse_gen_dir_name(&name) {
            if vfs.is_dir(&join(root, &name)) {
                out.push(g);
            }
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// Recursive file walk under `base/top`, returning `top/`-prefixed
/// forward-slash relative paths, sorted.
fn walk_files(vfs: &Arc<dyn Vfs>, base: &Path, top: &str) -> Result<Vec<String>, StoreError> {
    let mut out = Vec::new();
    let mut stack = vec![top.to_string()];
    while let Some(rel) = stack.pop() {
        let p = join(base, &rel);
        if vfs.is_dir(&p) {
            for name in vfs
                .read_dir(&p)
                .map_err(|e| StoreError::io("read_dir", &p, e))?
            {
                stack.push(format!("{rel}/{name}"));
            }
        } else {
            out.push(rel);
        }
    }
    out.sort();
    Ok(out)
}

fn rel_path_is_safe(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && !rel.contains('\\')
        && !rel.contains(':')
        && rel
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Validate one generation directory against its manifest.
///
/// Outer `Err` = typed fatal (identity mismatch; pointer/manifest
/// generation conflict when `pointer_sourced`). Inner `Err(String)` =
/// generation invalid, fallback permitted.
fn validate_generation(
    vfs: &Arc<dyn Vfs>,
    gen_dir: &Path,
    gen: u64,
    expected_manifest_hash: Option<[u8; 32]>,
    identity: &[u8],
    pointer_sourced: bool,
) -> Result<Result<ManifestV1, String>, StoreError> {
    let mpath = join(gen_dir, MANIFEST_FILE);
    let bytes = match vfs.read(&mpath) {
        Ok(b) => b,
        Err(e) => return Ok(Err(format!("manifest unreadable: {e}"))),
    };
    let (manifest, actual_hash) = match ManifestV1::from_file_bytes(&bytes) {
        Ok(pair) => pair,
        Err(reason) => return Ok(Err(reason)),
    };
    if let Some(expect) = expected_manifest_hash {
        if actual_hash != expect {
            return Ok(Err("manifest hash disagrees with pointer".to_string()));
        }
    }
    if manifest.generation != gen {
        if pointer_sourced {
            return Err(StoreError::Fatal(FatalError::ConflictingPointers {
                pointer_generation: gen,
                manifest_generation: manifest.generation,
            }));
        }
        return Ok(Err(format!(
            "manifest generation {} != directory generation {gen}",
            manifest.generation
        )));
    }
    if manifest.identity != identity {
        return Err(StoreError::Fatal(FatalError::IdentityMismatch));
    }
    for f in &manifest.engine_files {
        if !rel_path_is_safe(&f.rel_path) {
            return Ok(Err(format!("unsafe manifest path {:?}", f.rel_path)));
        }
        let p = join(gen_dir, &f.rel_path);
        let data = match vfs.read(&p) {
            Ok(d) => d,
            Err(e) => return Ok(Err(format!("pinned file {:?} unreadable: {e}", f.rel_path))),
        };
        if data.len() as u64 != f.size {
            return Ok(Err(format!("pinned file {:?} size mismatch", f.rel_path)));
        }
        if ctx_hash(crate::CTX_FILE, &data) != f.hash {
            return Ok(Err(format!("pinned file {:?} hash mismatch", f.rel_path)));
        }
    }
    // Segment watermarks: shared blob segments must still cover this
    // generation's pinned prefixes.
    let root = match gen_dir.parent() {
        Some(r) => r.to_path_buf(),
        None => return Ok(Err("generation directory has no parent".to_string())),
    };
    let seg_dir = join(&root, SEGMENTS_DIR);
    for s in &manifest.segments {
        let p = join(&seg_dir, &crate::blob::segment_file_name(s.segment));
        let len = match vfs.file_len(&p) {
            Ok(l) => l,
            Err(e) => return Ok(Err(format!("segment {} unreadable: {e}", s.segment))),
        };
        if len < s.len {
            return Ok(Err(format!("segment {} below watermark", s.segment)));
        }
        let bytes = match vfs.read_at(&p, 0, s.len as usize) {
            Ok(b) => b,
            Err(e) => return Ok(Err(format!("segment {} prefix unreadable: {e}", s.segment))),
        };
        if ctx_hash(crate::CTX_FILE, &bytes) != s.prefix_hash {
            return Ok(Err(format!("segment {} prefix hash mismatch", s.segment)));
        }
    }
    Ok(Ok(manifest))
}

/// Durable `CURRENT` replacement: temp-write → fsync → atomic same-volume
/// rename → parent-directory flush (best-effort on Windows, documented).
fn flip_current(
    vfs: &Arc<dyn Vfs>,
    root: &Path,
    generation: u64,
    manifest_hash: [u8; 32],
) -> Result<(), StoreError> {
    let ptr = CurrentPointerV1 {
        generation,
        manifest_hash,
    };
    let tmp = Store::p_current_tmp(root);
    let dst = Store::p_current(root);
    vfs.write_file(&tmp, &ptr.to_file_bytes())
        .map_err(|e| StoreError::io("write", &tmp, e))?;
    vfs.fsync_path(&tmp)
        .map_err(|e| StoreError::io("fsync", &tmp, e))?;
    vfs.rename(&tmp, &dst)
        .map_err(|e| StoreError::io("rename", &dst, e))?;
    vfs.sync_dir(root)
        .map_err(|e| StoreError::io("sync_dir", root, e))?;
    Ok(())
}

fn write_proven(
    vfs: &Arc<dyn Vfs>,
    gen_dir: &Path,
    manifest_hash: [u8; 32],
) -> Result<(), StoreError> {
    let p = join(gen_dir, PROVEN_FILE);
    vfs.write_file(&p, &manifest_hash)
        .map_err(|e| StoreError::io("write", &p, e))?;
    vfs.fsync_path(&p)
        .map_err(|e| StoreError::io("fsync", &p, e))?;
    vfs.sync_dir(gen_dir)
        .map_err(|e| StoreError::io("sync_dir", gen_dir, e))?;
    Ok(())
}

/// Compare two engines at the same seq: applied_seq, identity, roots, and
/// deterministic proof samples over the state CF.
fn verify_engines_equal(
    cfg: &StoreConfig,
    gen: u64,
    candidate: &Engine,
    reference: &Engine,
    expect_seq: u64,
) -> Result<(), String> {
    let a = candidate.applied_seq().map_err(|e| e.to_string())?;
    if a != expect_seq {
        return Err(format!("applied_seq {a} != expected {expect_seq}"));
    }
    let id_c = candidate.identity().map_err(|e| e.to_string())?;
    if id_c.as_deref() != Some(cfg.identity.as_slice()) {
        return Err("identity mismatch in candidate engine".to_string());
    }
    let roots_c = candidate.roots_bytes().map_err(|e| e.to_string())?;
    let roots_r = reference.roots_bytes().map_err(|e| e.to_string())?;
    if roots_c != roots_r {
        return Err("lumen roots differ".to_string());
    }
    for i in 0..cfg.proof_samples {
        let mut seed = Vec::with_capacity(12);
        seed.extend_from_slice(&gen.to_le_bytes());
        seed.extend_from_slice(&i.to_le_bytes());
        let target = ctx_hash(CTX_SAMPLE, &seed);
        // Sample point inside the state keyspace: tree byte then hash.
        let mut probe = Vec::with_capacity(33);
        probe.push(target[0] % 7);
        probe.extend_from_slice(&target);
        let sc = candidate
            .sample_at(Cf::State, &probe)
            .map_err(|e| e.to_string())?;
        let sr = reference
            .sample_at(Cf::State, &probe)
            .map_err(|e| e.to_string())?;
        if sc != sr {
            return Err(format!("proof sample {i} diverges"));
        }
    }
    Ok(())
}

/// Rebuild the live engine from a verified generation (byte-copy of every
/// manifest-pinned file). The WAL tail is replayed by the caller.
fn rebuild_live(
    vfs: &Arc<dyn Vfs>,
    root: &Path,
    gen: u64,
    manifest: &ManifestV1,
) -> Result<(), StoreError> {
    let live = Store::p_live(root);
    if vfs.is_dir(&live) {
        vfs.remove_dir_all(&live)
            .map_err(|e| StoreError::io("remove_dir_all", &live, e))?;
    }
    let gen_dir = Store::p_gen(root, gen);
    for f in &manifest.engine_files {
        let src = join(&gen_dir, &f.rel_path);
        // Strip the leading "engine/" so files land directly in live/.
        let stripped = f
            .rel_path
            .strip_prefix("engine/")
            .ok_or(StoreError::InvalidWriteSet("manifest path outside engine/"))?;
        let dst = join(&live, stripped);
        if let Some(parent) = dst.parent() {
            vfs.create_dir_all(parent)
                .map_err(|e| StoreError::io("create_dir_all", parent, e))?;
        }
        let bytes = vfs
            .read(&src)
            .map_err(|e| StoreError::io("read", &src, e))?;
        vfs.write_file(&dst, &bytes)
            .map_err(|e| StoreError::io("write", &dst, e))?;
        vfs.fsync_path(&dst)
            .map_err(|e| StoreError::io("fsync", &dst, e))?;
    }
    vfs.sync_dir(&live)
        .map_err(|e| StoreError::io("sync_dir", &live, e))?;
    Ok(())
}

/// Fresh-process proof: copy the generation to a scratch dir, replay the
/// WAL tail, compare against the live engine, then mark `PROVEN`.
fn prove_replay(
    vfs: &Arc<dyn Vfs>,
    cfg: &StoreConfig,
    root: &Path,
    gen: u64,
    manifest: &ManifestV1,
    scan: &wal::WalScan,
    live: &Engine,
) -> Result<(), StoreError> {
    let scratch = join(root, &format!("tmp-prove-{gen:020}"));
    if vfs.exists(&scratch) {
        vfs.remove_dir_all(&scratch)
            .map_err(|e| StoreError::io("remove_dir_all", &scratch, e))?;
    }
    vfs.create_dir_all(&scratch)
        .map_err(|e| StoreError::io("create_dir_all", &scratch, e))?;
    let gen_dir = Store::p_gen(root, gen);
    let scratch_engine = join(&scratch, ENGINE_SUBDIR);
    for f in &manifest.engine_files {
        let src = join(&gen_dir, &f.rel_path);
        let dst = join(&scratch, &f.rel_path);
        if let Some(parent) = dst.parent() {
            vfs.create_dir_all(parent)
                .map_err(|e| StoreError::io("create_dir_all", parent, e))?;
        }
        let bytes = vfs
            .read(&src)
            .map_err(|e| StoreError::io("read", &src, e))?;
        vfs.write_file(&dst, &bytes)
            .map_err(|e| StoreError::io("write", &dst, e))?;
    }
    fail_at(vfs, "prove_open")?;
    let result = (|| -> Result<(), StoreError> {
        let eng = Engine::open(&scratch_engine, &Store::p_logs(root), false)?;
        let mut expected = manifest
            .applied_seq
            .checked_add(1)
            .ok_or(StoreError::Arithmetic("seq successor"))?;
        fail_at(vfs, "prove_replay")?;
        for rec in scan.records.iter().filter(|r| r.seq > manifest.applied_seq) {
            if rec.seq != expected {
                return Err(StoreError::Fatal(FatalError::HistoryGap {
                    detail: format!("proof replay expected seq {expected}, found {}", rec.seq),
                }));
            }
            eng.apply(&rec.ops, rec.seq)?;
            expected = rec
                .seq
                .checked_add(1)
                .ok_or(StoreError::Arithmetic("seq successor"))?;
        }
        verify_engines_equal(cfg, gen, &eng, live, live.applied_seq()?)
            .map_err(|detail| StoreError::Fatal(FatalError::ReplayDivergence { detail }))?;
        Ok(())
    })();
    result?;
    write_proven(vfs, &gen_dir, manifest.hash())?;
    vfs.remove_dir_all(&scratch)
        .map_err(|e| StoreError::io("remove_dir_all", &scratch, e))?;
    Ok(())
}
