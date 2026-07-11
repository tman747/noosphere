//! Bounded proof-check worker pool (ch01 §3.1: "expensive proof checks run
//! in bounded pools but return deterministic `(profile_id, input_digest,
//! verdict, cost)` records before ordered application").
//!
//! Jobs are pure closures. A panicking job yields the typed
//! [`Verdict::WorkerCrashed`] record — a local inability to validate,
//! NEVER implicit acceptance and never consensus corruption; the worker
//! thread survives and keeps serving. The queue is bounded: submission
//! applies backpressure instead of growing without limit.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::Hash32;

/// Deterministic verdict outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Typed rejection code (per profile).
    Reject(u32),
    /// The worker crashed while checking: local inability to validate.
    WorkerCrashed,
}

/// Deterministic verdict record (ch01 §3.1 shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictRecordV1 {
    pub profile_id: u32,
    pub input_digest: Hash32,
    pub verdict: Verdict,
    /// Deterministic cost: declared input units (bytes), never wall time.
    pub cost: u64,
}

type Check = Box<dyn FnOnce() -> Result<(), u32> + Send>;

struct Job {
    profile_id: u32,
    input_digest: Hash32,
    cost: u64,
    check: Check,
    reply: SyncSender<VerdictRecordV1>,
}

/// Bounded worker pool.
pub struct VerdictPool {
    job_tx: SyncSender<Job>,
    workers: Vec<JoinHandle<()>>,
}

impl VerdictPool {
    /// Spawns `workers` threads over a queue bounded at `queue_cap`.
    #[must_use]
    pub fn new(workers: usize, queue_cap: usize) -> Self {
        let (job_tx, job_rx) = sync_channel::<Job>(queue_cap.max(1));
        let shared: Arc<Mutex<Receiver<Job>>> = Arc::new(Mutex::new(job_rx));
        let mut handles = Vec::with_capacity(workers.max(1));
        for i in 0..workers.max(1) {
            let rx = Arc::clone(&shared);
            let spawned = std::thread::Builder::new()
                .name(format!("noos-verdict-{i}"))
                .spawn(move || loop {
                    let job = {
                        let guard = match rx.lock() {
                            Ok(g) => g,
                            Err(_) => return, // sibling panicked while holding: shut down
                        };
                        match guard.recv() {
                            Ok(j) => j,
                            Err(_) => return, // pool dropped
                        }
                    };
                    let Job {
                        profile_id,
                        input_digest,
                        cost,
                        check,
                        reply,
                    } = job;
                    let verdict = match catch_unwind(AssertUnwindSafe(check)) {
                        Ok(Ok(())) => Verdict::Accept,
                        Ok(Err(code)) => Verdict::Reject(code),
                        Err(_) => Verdict::WorkerCrashed,
                    };
                    let _ = reply.send(VerdictRecordV1 {
                        profile_id,
                        input_digest,
                        verdict,
                        cost,
                    });
                });
            match spawned {
                Ok(handle) => handles.push(handle),
                // OS refused a thread: a smaller pool still fails closed
                // (a queue with zero workers answers WorkerCrashed).
                Err(_) => break,
            }
        }
        VerdictPool {
            job_tx,
            workers: handles,
        }
    }

    /// Submits a check and blocks for its deterministic verdict record.
    /// Returns `WorkerCrashed` when the pool is gone (fail closed).
    pub fn check(
        &self,
        profile_id: u32,
        input_digest: Hash32,
        cost: u64,
        check: impl FnOnce() -> Result<(), u32> + Send + 'static,
    ) -> VerdictRecordV1 {
        let (reply_tx, reply_rx) = sync_channel(1);
        let job = Job {
            profile_id,
            input_digest,
            cost,
            check: Box::new(check),
            reply: reply_tx,
        };
        if self.job_tx.send(job).is_err() {
            return VerdictRecordV1 {
                profile_id,
                input_digest,
                verdict: Verdict::WorkerCrashed,
                cost,
            };
        }
        reply_rx.recv().unwrap_or(VerdictRecordV1 {
            profile_id,
            input_digest,
            verdict: Verdict::WorkerCrashed,
            cost,
        })
    }

    /// Worker count (for status surfaces).
    #[must_use]
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }
}
