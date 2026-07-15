//! Exact Prism llama.cpp command and token conformance adapter.

use crate::config::ExecutorConfig;
use crate::executor::residency::verify_file;
use crate::executor::security::{validate_runtime_args, SecurityError};
use crate::runtime::process::{
    private_file_prompt_child_spec, ChildSpec, StdoutFilter,
};
use std::fmt;
const RUNTIME_STDOUT_OVERHEAD_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    ContextOverflow,
    TokenizerMismatch,
    NonConsecutiveToken,
    OutputLimit,
    RuntimeIdentity,
    Security(SecurityError),
}
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prism llama adapter: {self:?}")
    }
}
impl std::error::Error for AdapterError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeToken {
    pub sequence: u32,
    pub token_id: u32,
    pub utf8: Vec<u8>,
    pub eos: bool,
}

#[derive(Clone, Debug)]
pub struct LlamaCppAdapter {
    max_context_tokens: u32,
    max_output_tokens: u32,
}

impl LlamaCppAdapter {
    #[must_use]
    pub fn new(max_context_tokens: u32, max_output_tokens: u32) -> Self {
        Self {
            max_context_tokens,
            max_output_tokens,
        }
    }

    pub fn child_spec(
        &self,
        config: &ExecutorConfig,
        prompt_token_ids: &[u32],
        requested_output_tokens: u32,
    ) -> Result<ChildSpec, AdapterError> {
        if requested_output_tokens == 0
            || requested_output_tokens > self.max_output_tokens
            || u32::try_from(prompt_token_ids.len())
                .ok()
                .and_then(|prompt| prompt.checked_add(requested_output_tokens))
                .is_none_or(|total| total > self.max_context_tokens)
        {
            return Err(AdapterError::ContextOverflow);
        }
        let runtime_bytes = std::fs::metadata(&config.runtime.executable)
            .map_err(|_| AdapterError::RuntimeIdentity)?
            .len();
        verify_file(
            &config.runtime.executable,
            runtime_bytes,
            &config.runtime.binary_sha256_hex,
        )
        .map_err(|_| AdapterError::RuntimeIdentity)?;
        validate_runtime_args(&config.runtime.extra_args).map_err(AdapterError::Security)?;
        let mut args = vec![
            "--model".into(),
            config.model.path.to_string_lossy().into_owned(),
            "--ctx-size".into(),
            self.max_context_tokens.to_string(),
            "--n-predict".into(),
            requested_output_tokens.to_string(),
            "--no-display-prompt".into(),
            "--simple-io".into(),
            "--log-disable".into(),
            "--no-show-timings".into(),
            "--color".into(),
            "off".into(),
            "--skip-chat-parsing".into(),
            "--reasoning-format".into(),
            "none".into(),
            "--no-warmup".into(),
            "--offline".into(),
            "--single-turn".into(),
        ];
        args.extend(config.runtime.extra_args.iter().cloned());
        let model_output_bytes = usize::try_from(requested_output_tokens)
            .ok()
            .and_then(|tokens| tokens.checked_mul(256))
            .ok_or(AdapterError::OutputLimit)?;
        let transcript_bytes = model_output_bytes
            .checked_add(RUNTIME_STDOUT_OVERHEAD_BYTES)
            .ok_or(AdapterError::OutputLimit)?;
        let mut spec = private_file_prompt_child_spec(
            &config.runtime.executable,
            args,
            &config.worker.scratch_dir,
            config.scheduler.job_timeout_ms,
            config.scheduler.cancel_grace_ms,
            transcript_bytes,
            "--file",
        );
        spec.max_filtered_output_bytes = model_output_bytes;
        spec.stdout_filter = StdoutFilter::PinnedLlamaCliV1;
        Ok(spec)
    }

    /// Compare independently tokenized IDs before execution. No truncation or
    /// runtime-side tokenizer substitution is accepted.
    pub fn require_tokenizer_match(expected: &[u32], runtime: &[u32]) -> Result<(), AdapterError> {
        if expected == runtime {
            Ok(())
        } else {
            Err(AdapterError::TokenizerMismatch)
        }
    }
}

/// Applies exact ordering, EOS, UTF-8, stop, and output-token bounds while
/// maintaining the token-history root used by receipts.
pub struct TokenAccumulator {
    next_sequence: u32,
    max_tokens: u32,
    stop: Vec<Vec<u8>>,
    output: Vec<u8>,
    history: blake3::Hasher,
    stopped: bool,
}
impl TokenAccumulator {
    #[must_use]
    pub fn new(max_tokens: u32, stop: Vec<Vec<u8>>) -> Self {
        let mut history = blake3::Hasher::new();
        history.update(b"NOOS/WWM/TOKEN-HISTORY/V1\0");
        Self {
            next_sequence: 0,
            max_tokens,
            stop,
            output: Vec::new(),
            history,
            stopped: false,
        }
    }

    pub fn push(&mut self, token: &RuntimeToken) -> Result<bool, AdapterError> {
        if self.stopped {
            return Ok(false);
        }
        if token.sequence != self.next_sequence {
            return Err(AdapterError::NonConsecutiveToken);
        }
        if token.sequence >= self.max_tokens {
            return Err(AdapterError::OutputLimit);
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.history.update(&token.sequence.to_le_bytes());
        self.history.update(&token.token_id.to_le_bytes());
        self.history
            .update(&(token.utf8.len() as u64).to_le_bytes());
        self.history.update(&token.utf8);
        if token.eos {
            self.stopped = true;
            return Ok(false);
        }
        self.output.extend_from_slice(&token.utf8);
        if let Some(position) = self
            .stop
            .iter()
            .filter_map(|needle| find_subslice(&self.output, needle))
            .min()
        {
            self.output.truncate(position);
            self.stopped = true;
            return Ok(false);
        }
        Ok(true)
    }

    pub fn finish(self) -> Result<(String, [u8; 32]), AdapterError> {
        let text = String::from_utf8(self.output).map_err(|_| AdapterError::TokenizerMismatch)?;
        Ok((text, *self.history.finalize().as_bytes()))
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_ids_order_eos_stop_and_utf8_are_exact() {
        assert_eq!(
            LlamaCppAdapter::require_tokenizer_match(&[1, 2], &[1, 3]),
            Err(AdapterError::TokenizerMismatch)
        );
        let mut acc = TokenAccumulator::new(4, vec![b"STOP".to_vec()]);
        assert!(acc
            .push(&RuntimeToken {
                sequence: 0,
                token_id: 9,
                utf8: vec![0xe2],
                eos: false
            })
            .unwrap());
        assert!(acc
            .push(&RuntimeToken {
                sequence: 1,
                token_id: 10,
                utf8: vec![0x82, 0xac],
                eos: false
            })
            .unwrap());
        assert!(!acc
            .push(&RuntimeToken {
                sequence: 2,
                token_id: 11,
                utf8: b"STOPtail".to_vec(),
                eos: false
            })
            .unwrap());
        let (text, _) = acc.finish().unwrap();
        assert_eq!(text, "€");
        let mut eos = TokenAccumulator::new(1, vec![]);
        assert!(!eos
            .push(&RuntimeToken {
                sequence: 0,
                token_id: 2,
                utf8: b"ignored".to_vec(),
                eos: true
            })
            .unwrap());
        assert_eq!(eos.finish().unwrap().0, "");
    }

    #[test]
    fn runtime_swap_after_warmup_is_rejected_before_spawn() {
        let mut config =
            ExecutorConfig::parse(include_str!("../../workerd-v2.example.toml")).unwrap();
        let mut executable = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        executable.write_all(b"pinned-runtime").unwrap();
        config.runtime.executable = executable.path().to_owned();
        config.runtime.binary_sha256_hex =
            crate::executor::residency::sha256_file(executable.path(), 14).unwrap();
        let adapter = LlamaCppAdapter::new(4096, 512);
        let spec = adapter.child_spec(&config, &[1], 1).unwrap();
        assert_eq!(spec.prompt_file_flag, Some("--file"));
        assert!(!spec.args.iter().any(|argument| argument == "-"));
        assert!(spec.args.iter().any(|argument| argument == "--log-disable"));
        assert!(spec
            .args
            .iter()
            .any(|argument| argument == "--no-show-timings"));
        assert!(spec.args.windows(2).any(|args| args == ["--color", "off"]));
        assert!(spec.args.iter().any(|argument| argument == "--skip-chat-parsing"));
        assert!(spec
            .args
            .windows(2)
            .any(|args| args == ["--reasoning-format", "none"]));
        assert_eq!(spec.stdout_filter, StdoutFilter::PinnedLlamaCliV1);
        assert_eq!(spec.max_filtered_output_bytes, 256);
        executable.as_file_mut().set_len(0).unwrap();
        use std::io::{Seek, SeekFrom};
        executable.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        executable.write_all(b"forged-runtime").unwrap();
        assert_eq!(
            adapter.child_spec(&config, &[1], 1).err(),
            Some(AdapterError::RuntimeIdentity)
        );
    }
}
