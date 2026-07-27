//! Private execution memory and host-persistence policy.
//!
//! Prompt, context, activations, KV state, logits, and output are represented
//! only as non-cloneable in-memory buffers that wipe on every terminal path.
//! Host admission fails unless plaintext logs, scratch, crash dumps, swap, and
//! cross-job caches are disabled or protected. Telemetry is either disabled or
//! delayed threshold aggregation without a job, user, destination, or content
//! field. Real host enforcement and crash/reboot scans remain evidence gates.

use crate::Hash32;
use noos_crypto::{hash_domain, DomainId};

pub const PRIVATE_SECRET_KINDS: usize = 6;
pub const MAX_PRIVATE_STATE_BYTES_PER_KIND: usize = 64 * 1024 * 1024;
pub const MIN_PRIVATE_TELEMETRY_BATCH: u32 = 32;
pub const MIN_PRIVATE_TELEMETRY_DELAY_SECONDS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateRuntimeError {
    UnsafeHostPolicy,
    InvalidSecret,
    ArithmeticOverflow,
    AlreadyTerminated,
    TelemetryDisabled,
    TelemetryNotReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateSecretKind {
    Prompt = 1,
    Context = 2,
    Activation = 3,
    Kv = 4,
    Logits = 5,
    Output = 6,
}

impl PrivateSecretKind {
    const ALL: [Self; PRIVATE_SECRET_KINDS] = [
        Self::Prompt,
        Self::Context,
        Self::Activation,
        Self::Kv,
        Self::Logits,
        Self::Output,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Prompt => 0,
            Self::Context => 1,
            Self::Activation => 2,
            Self::Kv => 3,
            Self::Logits => 4,
            Self::Output => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateTelemetryPolicy {
    Disabled,
    DelayedThresholdAggregate {
        minimum_events: u32,
        delay_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateHostPolicy {
    pub plaintext_logs_disabled: bool,
    pub plaintext_scratch_disabled: bool,
    pub crash_dumps_disabled: bool,
    pub swap_encryption_verified: bool,
    pub cross_job_cache_disabled: bool,
    pub core_memory_lock_required: bool,
    pub telemetry: PrivateTelemetryPolicy,
}

impl PrivateHostPolicy {
    #[must_use]
    pub const fn strict_disabled_telemetry() -> Self {
        Self {
            plaintext_logs_disabled: true,
            plaintext_scratch_disabled: true,
            crash_dumps_disabled: true,
            swap_encryption_verified: true,
            cross_job_cache_disabled: true,
            core_memory_lock_required: true,
            telemetry: PrivateTelemetryPolicy::Disabled,
        }
    }

    pub fn validate(self) -> Result<(), PrivateRuntimeError> {
        if !self.plaintext_logs_disabled
            || !self.plaintext_scratch_disabled
            || !self.crash_dumps_disabled
            || !self.swap_encryption_verified
            || !self.cross_job_cache_disabled
            || !self.core_memory_lock_required
        {
            return Err(PrivateRuntimeError::UnsafeHostPolicy);
        }
        if let PrivateTelemetryPolicy::DelayedThresholdAggregate {
            minimum_events,
            delay_seconds,
        } = self.telemetry
        {
            if minimum_events < MIN_PRIVATE_TELEMETRY_BATCH
                || delay_seconds < MIN_PRIVATE_TELEMETRY_DELAY_SECONDS
            {
                return Err(PrivateRuntimeError::UnsafeHostPolicy);
            }
        }
        Ok(())
    }
}

struct SecretBuffer {
    bytes: Vec<u8>,
    zeroized: bool,
}

impl SecretBuffer {
    fn new(bytes: Vec<u8>) -> Result<Self, PrivateRuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_STATE_BYTES_PER_KIND {
            return Err(PrivateRuntimeError::InvalidSecret);
        }
        Ok(Self {
            bytes,
            zeroized: false,
        })
    }

    fn replace(&mut self, bytes: Vec<u8>) -> Result<(), PrivateRuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_STATE_BYTES_PER_KIND {
            return Err(PrivateRuntimeError::InvalidSecret);
        }
        self.bytes.fill(0);
        self.bytes = bytes;
        self.zeroized = false;
        Ok(())
    }

    fn commitment(&self, kind: PrivateSecretKind) -> Result<Hash32, PrivateRuntimeError> {
        if self.zeroized {
            return Err(PrivateRuntimeError::AlreadyTerminated);
        }
        hash_domain(
            DomainId::WwmPrivateEnvelope,
            &[b"EPHEMERAL-STATE", &[kind as u8], &self.bytes],
        )
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| PrivateRuntimeError::InvalidSecret)
    }

    fn zeroize(&mut self) {
        self.bytes.fill(0);
        self.zeroized = true;
    }

    fn is_zeroized(&self) -> bool {
        self.zeroized && self.bytes.iter().all(|byte| *byte == 0)
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateTermination {
    Completed = 1,
    Cancelled = 2,
    TimedOut = 3,
    Failed = 4,
    AttestationPolicyChanged = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateWipeReceipt {
    pub reason: PrivateTermination,
    pub wiped_kinds: u8,
    pub all_zeroized: bool,
}

/// A private execution's complete plaintext state. It intentionally has no
/// `Clone`, `Debug`, serialization, cache, log, or persistence implementation.
pub struct PrivateExecutionMemory {
    policy: PrivateHostPolicy,
    buffers: [SecretBuffer; PRIVATE_SECRET_KINDS],
    terminated: bool,
}

impl PrivateExecutionMemory {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: PrivateHostPolicy,
        prompt: Vec<u8>,
        context: Vec<u8>,
        activation: Vec<u8>,
        kv: Vec<u8>,
        logits: Vec<u8>,
        output: Vec<u8>,
    ) -> Result<Self, PrivateRuntimeError> {
        policy.validate()?;
        Ok(Self {
            policy,
            buffers: [
                SecretBuffer::new(prompt)?,
                SecretBuffer::new(context)?,
                SecretBuffer::new(activation)?,
                SecretBuffer::new(kv)?,
                SecretBuffer::new(logits)?,
                SecretBuffer::new(output)?,
            ],
            terminated: false,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> PrivateHostPolicy {
        self.policy
    }

    pub fn view(&self, kind: PrivateSecretKind) -> Result<&[u8], PrivateRuntimeError> {
        if self.terminated {
            return Err(PrivateRuntimeError::AlreadyTerminated);
        }
        Ok(&self.buffers[kind.index()].bytes)
    }

    pub fn replace(
        &mut self,
        kind: PrivateSecretKind,
        bytes: Vec<u8>,
    ) -> Result<(), PrivateRuntimeError> {
        if self.terminated {
            return Err(PrivateRuntimeError::AlreadyTerminated);
        }
        self.buffers[kind.index()].replace(bytes)
    }

    /// Internal commitment for encrypted receipts. It is never accepted by
    /// the telemetry API because content-derived values are forbidden there.
    pub fn commitment(&self, kind: PrivateSecretKind) -> Result<Hash32, PrivateRuntimeError> {
        if self.terminated {
            return Err(PrivateRuntimeError::AlreadyTerminated);
        }
        self.buffers[kind.index()].commitment(kind)
    }

    pub fn terminate(
        &mut self,
        reason: PrivateTermination,
    ) -> Result<PrivateWipeReceipt, PrivateRuntimeError> {
        if self.terminated {
            return Err(PrivateRuntimeError::AlreadyTerminated);
        }
        for buffer in &mut self.buffers {
            buffer.zeroize();
        }
        self.terminated = true;
        Ok(PrivateWipeReceipt {
            reason,
            wiped_kinds: u8::try_from(PRIVATE_SECRET_KINDS)
                .map_err(|_| PrivateRuntimeError::ArithmeticOverflow)?,
            all_zeroized: self.buffers.iter().all(SecretBuffer::is_zeroized),
        })
    }

    #[must_use]
    pub fn is_zeroized(&self) -> bool {
        self.terminated && self.buffers.iter().all(SecretBuffer::is_zeroized)
    }
}

impl Drop for PrivateExecutionMemory {
    fn drop(&mut self) {
        for buffer in &mut self.buffers {
            buffer.zeroize();
        }
        self.terminated = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateTelemetryOutcome {
    Completed = 1,
    Cancelled = 2,
    TimedOut = 3,
    Failed = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoarsePrivateTelemetry {
    pub window_started_at: u64,
    pub window_ended_at: u64,
    pub completed: u32,
    pub cancelled: u32,
    pub timed_out: u32,
    pub failed: u32,
}

impl CoarsePrivateTelemetry {
    #[must_use]
    pub fn total(self) -> u32 {
        self.completed
            .saturating_add(self.cancelled)
            .saturating_add(self.timed_out)
            .saturating_add(self.failed)
    }
}

/// The record API accepts only a four-value outcome. There is no slot for a
/// job ID, user, destination, route, model, prompt-derived value, or duration.
pub struct PrivateTelemetryWindow {
    policy: PrivateTelemetryPolicy,
    started_at: u64,
    completed: u32,
    cancelled: u32,
    timed_out: u32,
    failed: u32,
    sealed: bool,
}

impl PrivateTelemetryWindow {
    pub fn new(
        policy: PrivateTelemetryPolicy,
        started_at: u64,
    ) -> Result<Self, PrivateRuntimeError> {
        PrivateHostPolicy {
            telemetry: policy,
            ..PrivateHostPolicy::strict_disabled_telemetry()
        }
        .validate()?;
        if started_at == 0 {
            return Err(PrivateRuntimeError::UnsafeHostPolicy);
        }
        Ok(Self {
            policy,
            started_at,
            completed: 0,
            cancelled: 0,
            timed_out: 0,
            failed: 0,
            sealed: false,
        })
    }

    pub fn record(&mut self, outcome: PrivateTelemetryOutcome) -> Result<(), PrivateRuntimeError> {
        if self.policy == PrivateTelemetryPolicy::Disabled {
            return Err(PrivateRuntimeError::TelemetryDisabled);
        }
        if self.sealed {
            return Err(PrivateRuntimeError::TelemetryNotReady);
        }
        let count = match outcome {
            PrivateTelemetryOutcome::Completed => &mut self.completed,
            PrivateTelemetryOutcome::Cancelled => &mut self.cancelled,
            PrivateTelemetryOutcome::TimedOut => &mut self.timed_out,
            PrivateTelemetryOutcome::Failed => &mut self.failed,
        };
        *count = count
            .checked_add(1)
            .ok_or(PrivateRuntimeError::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn release(&mut self, now: u64) -> Result<CoarsePrivateTelemetry, PrivateRuntimeError> {
        let PrivateTelemetryPolicy::DelayedThresholdAggregate {
            minimum_events,
            delay_seconds,
        } = self.policy
        else {
            return Err(PrivateRuntimeError::TelemetryDisabled);
        };
        let report = CoarsePrivateTelemetry {
            window_started_at: self.started_at,
            window_ended_at: now,
            completed: self.completed,
            cancelled: self.cancelled,
            timed_out: self.timed_out,
            failed: self.failed,
        };
        if self.sealed
            || now < self.started_at.saturating_add(delay_seconds)
            || report.total() < minimum_events
        {
            return Err(PrivateRuntimeError::TelemetryNotReady);
        }
        self.sealed = true;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(policy: PrivateHostPolicy) -> PrivateExecutionMemory {
        PrivateExecutionMemory::new(
            policy,
            b"PROMPT_CANARY".to_vec(),
            b"CONTEXT_CANARY".to_vec(),
            b"ACTIVATION_CANARY".to_vec(),
            b"KV_CANARY".to_vec(),
            b"LOGITS_CANARY".to_vec(),
            b"OUTPUT_CANARY".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn host_admission_rejects_each_plaintext_persistence_path() {
        let strict = PrivateHostPolicy::strict_disabled_telemetry();
        strict.validate().unwrap();
        for mutation in 0..6 {
            let mut candidate = strict;
            match mutation {
                0 => candidate.plaintext_logs_disabled = false,
                1 => candidate.plaintext_scratch_disabled = false,
                2 => candidate.crash_dumps_disabled = false,
                3 => candidate.swap_encryption_verified = false,
                4 => candidate.cross_job_cache_disabled = false,
                _ => candidate.core_memory_lock_required = false,
            }
            assert_eq!(
                candidate.validate(),
                Err(PrivateRuntimeError::UnsafeHostPolicy)
            );
        }
    }

    #[test]
    fn every_terminal_path_wipes_all_six_secret_classes() {
        for reason in [
            PrivateTermination::Completed,
            PrivateTermination::Cancelled,
            PrivateTermination::TimedOut,
            PrivateTermination::Failed,
            PrivateTermination::AttestationPolicyChanged,
        ] {
            let mut state = memory(PrivateHostPolicy::strict_disabled_telemetry());
            for kind in PrivateSecretKind::ALL {
                assert!(!state.view(kind).unwrap().is_empty());
                assert_ne!(state.commitment(kind).unwrap(), [0; 32]);
            }
            let receipt = state.terminate(reason).unwrap();
            assert_eq!(receipt.wiped_kinds, 6);
            assert!(receipt.all_zeroized);
            assert!(state.is_zeroized());
            assert_eq!(
                state.view(PrivateSecretKind::Prompt),
                Err(PrivateRuntimeError::AlreadyTerminated)
            );
        }
    }

    #[test]
    fn state_replacement_wipes_predecessor_and_remains_memory_only() {
        let mut state = memory(PrivateHostPolicy::strict_disabled_telemetry());
        state
            .replace(PrivateSecretKind::Kv, b"NEXT_KV_CANARY".to_vec())
            .unwrap();
        assert_eq!(
            state.view(PrivateSecretKind::Kv).unwrap(),
            b"NEXT_KV_CANARY"
        );
        state
            .terminate(PrivateTermination::AttestationPolicyChanged)
            .unwrap();
        assert!(state.is_zeroized());
    }

    #[test]
    fn telemetry_is_disabled_by_default_or_delayed_and_thresholded() {
        let mut disabled =
            PrivateTelemetryWindow::new(PrivateTelemetryPolicy::Disabled, 100).unwrap();
        assert_eq!(
            disabled.record(PrivateTelemetryOutcome::Completed),
            Err(PrivateRuntimeError::TelemetryDisabled)
        );

        let policy = PrivateTelemetryPolicy::DelayedThresholdAggregate {
            minimum_events: MIN_PRIVATE_TELEMETRY_BATCH,
            delay_seconds: MIN_PRIVATE_TELEMETRY_DELAY_SECONDS,
        };
        let mut aggregate = PrivateTelemetryWindow::new(policy, 100).unwrap();
        for _ in 0..MIN_PRIVATE_TELEMETRY_BATCH {
            aggregate
                .record(PrivateTelemetryOutcome::Completed)
                .unwrap();
        }
        assert_eq!(
            aggregate.release(159),
            Err(PrivateRuntimeError::TelemetryNotReady)
        );
        let report = aggregate.release(160).unwrap();
        assert_eq!(report.total(), MIN_PRIVATE_TELEMETRY_BATCH);
        assert_eq!(report.cancelled, 0);
        assert_eq!(
            aggregate.release(161),
            Err(PrivateRuntimeError::TelemetryNotReady)
        );
    }

    #[test]
    fn weak_aggregate_telemetry_policy_rejects() {
        for policy in [
            PrivateTelemetryPolicy::DelayedThresholdAggregate {
                minimum_events: MIN_PRIVATE_TELEMETRY_BATCH - 1,
                delay_seconds: MIN_PRIVATE_TELEMETRY_DELAY_SECONDS,
            },
            PrivateTelemetryPolicy::DelayedThresholdAggregate {
                minimum_events: MIN_PRIVATE_TELEMETRY_BATCH,
                delay_seconds: MIN_PRIVATE_TELEMETRY_DELAY_SECONDS - 1,
            },
        ] {
            assert!(matches!(
                PrivateTelemetryWindow::new(policy, 100),
                Err(PrivateRuntimeError::UnsafeHostPolicy)
            ));
        }
    }
}
