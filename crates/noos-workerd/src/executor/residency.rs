//! Exact artifact/runtime residency and readiness state machine.

use crate::config::ExecutorConfig;
use crate::executor::bootstrap::VerifiedExecutorBootstrapV1;
use noos_nel::runtime::inspect_bonsai;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResidencyState {
    Absent,
    Fetching,
    Verifying,
    Loading,
    Warming,
    Ready,
    Draining,
    Faulted,
}

impl ResidencyState {
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Absent, Self::Fetching)
                | (Self::Absent, Self::Verifying)
                | (Self::Fetching, Self::Verifying)
                | (Self::Verifying, Self::Loading)
                | (Self::Loading, Self::Warming)
                | (Self::Warming, Self::Ready)
                | (Self::Ready, Self::Draining)
                | (Self::Draining, Self::Absent)
        ) || (next == Self::Faulted && self != Self::Faulted)
    }
}

#[derive(Debug)]
pub enum ResidencyError {
    InvalidTransition {
        from: ResidencyState,
        to: ResidencyState,
    },
    Io(io::Error),
    Length {
        expected: u64,
        actual: u64,
    },
    Digest,
    WritableWeights,
    Resolution(String),
    NotReady(&'static str),
}

impl fmt::Display for ResidencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid residency transition {from:?} -> {to:?}")
            }
            Self::Io(error) => write!(f, "residency I/O: {error}"),
            Self::Length { expected, actual } => {
                write!(f, "artifact length {actual}, expected {expected}")
            }
            Self::Digest => f.write_str("artifact/runtime digest mismatch"),
            Self::WritableWeights => f.write_str("model weights must be read-only"),
            Self::Resolution(message) => write!(f, "finalized resolution: {message}"),
            Self::NotReady(reason) => write!(f, "not ready: {reason}"),
        }
    }
}
impl std::error::Error for ResidencyError {}
impl From<io::Error> for ResidencyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug)]
pub struct Residency {
    state: ResidencyState,
    last_error: Option<String>,
}

impl Default for Residency {
    fn default() -> Self {
        Self {
            state: ResidencyState::Absent,
            last_error: None,
        }
    }
}

impl Residency {
    #[must_use]
    pub const fn state(&self) -> ResidencyState {
        self.state
    }

    pub fn transition(&mut self, next: ResidencyState) -> Result<(), ResidencyError> {
        if !self.state.can_transition_to(next) {
            return Err(ResidencyError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        if next != ResidencyState::Faulted {
            self.last_error = None;
        }
        Ok(())
    }

    pub fn fault(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
        self.state = ResidencyState::Faulted;
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

pub fn sha256_file(path: &Path, expected_bytes: u64) -> Result<String, ResidencyError> {
    let mut file = File::open(path)?;
    let actual = file.metadata()?.len();
    if actual != expected_bytes {
        return Err(ResidencyError::Length {
            expected: expected_bytes,
            actual,
        });
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn verify_file(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), ResidencyError> {
    let actual = sha256_file(path, expected_bytes)?;
    if actual != expected_sha256 {
        return Err(ResidencyError::Digest);
    }
    Ok(())
}

/// Verify every immutable identity on a cold load. Warm-up and transition to
/// READY occur only after the runtime adapter reports conformance.
pub fn verify_cold_load(
    config: &ExecutorConfig,
    residency: &mut Residency,
    _bootstrap: &VerifiedExecutorBootstrapV1,
) -> Result<(), ResidencyError> {
    residency.transition(ResidencyState::Verifying)?;
    let result = (|| {
        inspect_bonsai(&config.model.path)
            .map_err(|error| ResidencyError::Resolution(format!("Bonsai conformance: {error}")))?;
        if !std::fs::metadata(&config.model.path)?
            .permissions()
            .readonly()
        {
            return Err(ResidencyError::WritableWeights);
        }
        verify_file(
            &config.runtime.executable,
            std::fs::metadata(&config.runtime.executable)?.len(),
            &config.runtime.binary_sha256_hex,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        residency.fault(error.to_string());
        return Err(error);
    }
    residency.transition(ResidencyState::Loading)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn state_machine_rejects_skips_and_allows_faults() {
        let mut state = Residency::default();
        assert!(matches!(
            state.transition(ResidencyState::Ready),
            Err(ResidencyError::InvalidTransition { .. })
        ));
        state.transition(ResidencyState::Verifying).unwrap();
        state.transition(ResidencyState::Loading).unwrap();
        state.transition(ResidencyState::Warming).unwrap();
        state.transition(ResidencyState::Ready).unwrap();
        state.transition(ResidencyState::Draining).unwrap();
        state.transition(ResidencyState::Absent).unwrap();
        state.fault("child crash");
        assert_eq!(state.state(), ResidencyState::Faulted);
        assert_eq!(state.last_error(), Some("child crash"));
    }

    #[test]
    fn exact_file_identity_rejects_mutation_and_length() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"bonsai").unwrap();
        let digest = sha256_file(file.path(), 6).unwrap();
        verify_file(file.path(), 6, &digest).unwrap();
        assert!(matches!(
            verify_file(file.path(), 7, &digest),
            Err(ResidencyError::Length { .. })
        ));
        assert!(matches!(
            verify_file(file.path(), 6, &"00".repeat(32)),
            Err(ResidencyError::Digest)
        ));
    }
}
