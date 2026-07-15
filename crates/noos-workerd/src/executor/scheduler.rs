//! Admission-before-prompt bounded scheduling and cancellation.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    Backpressure,
    DuplicateJob,
    ContextOverflow,
    Draining,
    Closed,
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Backpressure => "executor queue is full",
            Self::DuplicateJob => "job already admitted",
            Self::ContextOverflow => "prompt plus output exceeds context; truncation is forbidden",
            Self::Draining => "executor is draining",
            Self::Closed => "executor scheduler is closed",
        })
    }
}
impl std::error::Error for AdmissionError {}

struct Inner {
    concurrent: Arc<Semaphore>,
    max_admitted: usize,
    max_context_tokens: u32,
    max_output_tokens: u32,
    admitted: AtomicUsize,
    active: Mutex<HashSet<String>>,
    draining: AtomicBool,
}

#[derive(Clone)]
pub struct Scheduler(Arc<Inner>);

impl Scheduler {
    #[must_use]
    pub fn new(
        max_concurrent: usize,
        max_queue: usize,
        max_context_tokens: u32,
        max_output_tokens: u32,
    ) -> Self {
        Self(Arc::new(Inner {
            concurrent: Arc::new(Semaphore::new(max_concurrent)),
            max_admitted: max_concurrent.saturating_add(max_queue),
            max_context_tokens,
            max_output_tokens,
            admitted: AtomicUsize::new(0),
            active: Mutex::new(HashSet::new()),
            draining: AtomicBool::new(false),
        }))
    }

    pub fn try_admit(
        &self,
        job_id: String,
        prompt_tokens: u32,
        output_tokens: u32,
    ) -> Result<QueuedJob, AdmissionError> {
        if self.0.draining.load(Ordering::Acquire) {
            return Err(AdmissionError::Draining);
        }
        if output_tokens == 0
            || output_tokens > self.0.max_output_tokens
            || prompt_tokens
                .checked_add(output_tokens)
                .is_none_or(|total| total > self.0.max_context_tokens)
        {
            return Err(AdmissionError::ContextOverflow);
        }
        let mut current = self.0.admitted.load(Ordering::Acquire);
        loop {
            if current >= self.0.max_admitted {
                return Err(AdmissionError::Backpressure);
            }
            match self.0.admitted.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let inserted = self
            .0
            .active
            .lock()
            .map_err(|_| AdmissionError::Closed)?
            .insert(job_id.clone());
        if !inserted {
            self.0.admitted.fetch_sub(1, Ordering::AcqRel);
            return Err(AdmissionError::DuplicateJob);
        }
        Ok(QueuedJob {
            slot: Some(AdmissionSlot {
                scheduler: self.clone(),
                job_id,
            }),
            cancellation: Cancellation::new(),
        })
    }

    pub fn drain(&self) {
        self.0.draining.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.0.draining.load(Ordering::Acquire)
    }
    #[must_use]
    pub fn admitted(&self) -> usize {
        self.0.admitted.load(Ordering::Acquire)
    }
    #[must_use]
    pub fn available_concurrency(&self) -> usize {
        self.0.concurrent.available_permits()
    }
}

struct AdmissionSlot {
    scheduler: Scheduler,
    job_id: String,
}
impl Drop for AdmissionSlot {
    fn drop(&mut self) {
        if let Ok(mut active) = self.scheduler.0.active.lock() {
            active.remove(&self.job_id);
        }
        self.scheduler.0.admitted.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct QueuedJob {
    slot: Option<AdmissionSlot>,
    cancellation: Cancellation,
}
impl QueuedJob {
    #[must_use]
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }

    pub async fn start(mut self) -> Result<RunningJob, AdmissionError> {
        if self.cancellation.is_cancelled() {
            return Err(AdmissionError::Closed);
        }
        let permit = tokio::select! {
            permit = self.slot.as_ref().expect("queued slot").scheduler.0.concurrent.clone().acquire_owned() => permit.map_err(|_| AdmissionError::Closed)?,
            () = self.cancellation.cancelled() => return Err(AdmissionError::Closed),
        };
        Ok(RunningJob {
            _permit: permit,
            _slot: self.slot.take().expect("queued slot"),
            cancellation: self.cancellation.clone(),
        })
    }
}

pub struct RunningJob {
    _permit: OwnedSemaphorePermit,
    _slot: AdmissionSlot,
    cancellation: Cancellation,
}
impl RunningJob {
    #[must_use]
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
}

struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
}
#[derive(Clone)]
pub struct Cancellation(Arc<CancelInner>);
impl Cancellation {
    pub fn new() -> Self {
        Self(Arc::new(CancelInner {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }))
    }
    pub fn cancel(&self) {
        if !self.0.cancelled.swap(true, Ordering::AcqRel) {
            self.0.notify.notify_waiters();
        }
    }
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.0.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admission_is_bounded_before_queueing() {
        let scheduler = Scheduler::new(1, 1, 16, 8);
        let first = scheduler.try_admit("one".into(), 4, 4).unwrap();
        let second = scheduler.try_admit("two".into(), 4, 4).unwrap();
        assert_eq!(
            scheduler.try_admit("three".into(), 4, 4).err(),
            Some(AdmissionError::Backpressure)
        );
        let running = first.start().await.unwrap();
        assert_eq!(scheduler.available_concurrency(), 0);
        drop(running);
        second.start().await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_context_cancel_and_drain_fail_closed() {
        let scheduler = Scheduler::new(1, 2, 10, 5);
        let queued = scheduler.try_admit("same".into(), 5, 5).unwrap();
        assert_eq!(
            scheduler.try_admit("same".into(), 1, 1).err(),
            Some(AdmissionError::DuplicateJob)
        );
        assert_eq!(
            scheduler.try_admit("overflow".into(), 6, 5).err(),
            Some(AdmissionError::ContextOverflow)
        );
        let cancellation = queued.cancellation();
        cancellation.cancel();
        assert_eq!(queued.start().await.err(), Some(AdmissionError::Closed));
        scheduler.drain();
        assert_eq!(
            scheduler.try_admit("new".into(), 1, 1).err(),
            Some(AdmissionError::Draining)
        );
    }
}
