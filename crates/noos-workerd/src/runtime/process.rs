//! Bounded child execution with streaming, cancellation, timeout, and kill grace.

use crate::executor::scheduler::Cancellation;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdoutFilter {
    Raw,
    PinnedLlamaCliV1,
}

#[derive(Clone, Debug)]
pub struct ChildSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub scratch_dir: PathBuf,
    pub timeout: Duration,
    pub cancel_grace: Duration,
    pub max_output_bytes: usize,
    pub max_filtered_output_bytes: usize,
    pub stdout_filter: StdoutFilter,
    pub prompt_file_flag: Option<&'static str>,
}

static PROMPT_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PromptFile {
    path: PathBuf,
    bytes: usize,
}

impl PromptFile {
    fn create(directory: &Path, prompt: &[u8]) -> Result<Self, ChildError> {
        for _ in 0..16 {
            let sequence = PROMPT_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                ".noos-prompt-{}-{sequence}.tmp",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(prompt)
                        .and_then(|()| file.flush())
                        .map_err(|error| ChildError::Stdin(error.to_string()))?;
                    return Ok(Self {
                        path,
                        bytes: prompt.len(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(ChildError::Stdin(error.to_string())),
            }
        }
        Err(ChildError::Stdin(
            "cannot allocate a private prompt file".to_owned(),
        ))
    }
}

impl Drop for PromptFile {
    fn drop(&mut self) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(&self.path) {
            let mut remaining = self.bytes;
            let zeros = [0_u8; 4_096];
            let _ = file.seek(SeekFrom::Start(0));
            while remaining != 0 {
                let count = remaining.min(zeros.len());
                if file.write_all(&zeros[..count]).is_err() {
                    break;
                }
                remaining = remaining.saturating_sub(count);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputChunk {
    pub sequence: u64,
    pub bytes: Vec<u8>,
    pub incremental_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildError {
    Spawn(String),
    Stdin(String),
    Read(String),
    Crash(Option<i32>),
    Timeout,
    Cancelled,
    OutputLimit,
    InvalidUtf8,
    StreamClosed,
    TranscriptFraming,
}
impl fmt::Display for ChildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "child runtime: {self:?}")
    }
}
impl std::error::Error for ChildError {}
fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn filter_pinned_llama_cli_transcript(
    transcript: &[u8],
    prompt: &[u8],
) -> Result<Vec<u8>, ChildError> {
    if prompt.is_empty()
        || prompt.len() > 500
        || prompt.contains(&b'\r')
        || prompt.contains(&b'\n')
        || transcript.contains(&0x1b)
    {
        return Err(ChildError::TranscriptFraming);
    }
    let newline: &[u8] = if transcript.windows(2).any(|window| window == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut loading = Vec::with_capacity(newline.len() + 17);
    loading.extend_from_slice(newline);
    loading.extend_from_slice(b"Loading model... ");
    if !transcript.starts_with(&loading) {
        return Err(ChildError::TranscriptFraming);
    }
    let mut delimiter = Vec::with_capacity(
        newline
            .len()
            .saturating_mul(3)
            .saturating_add(prompt.len())
            .saturating_add(2),
    );
    delimiter.extend_from_slice(newline);
    delimiter.extend_from_slice(b"> ");
    delimiter.extend_from_slice(prompt);
    delimiter.extend_from_slice(newline);
    delimiter.extend_from_slice(newline);
    let mut suffix = Vec::with_capacity(newline.len().saturating_mul(3).saturating_add(10));
    suffix.extend_from_slice(newline);
    suffix.extend_from_slice(newline);
    suffix.extend_from_slice(b"Exiting...");
    suffix.extend_from_slice(newline);
    if count_subslice(transcript, &delimiter) != 1
        || count_subslice(transcript, &suffix) != 1
        || !transcript.ends_with(&suffix)
    {
        return Err(ChildError::TranscriptFraming);
    }
    let start = transcript
        .windows(delimiter.len())
        .position(|window| window == delimiter)
        .and_then(|position| position.checked_add(delimiter.len()))
        .ok_or(ChildError::TranscriptFraming)?;
    let end = transcript
        .len()
        .checked_sub(suffix.len())
        .ok_or(ChildError::TranscriptFraming)?;
    if start >= end {
        return Err(ChildError::TranscriptFraming);
    }
    let output = &transcript[start..end];
    if output.windows(prompt.len()).any(|window| window == prompt)
        || output
            .windows(b"[Start thinking]".len())
            .any(|window| window == b"[Start thinking]")
        || output
            .windows(b"[End thinking]".len())
            .any(|window| window == b"[End thinking]")
        || output
            .windows(b"Loading model...".len())
            .any(|window| window == b"Loading model...")
    {
        return Err(ChildError::TranscriptFraming);
    }
    Ok(output.to_vec())
}

/// Run a network-inert child. The environment is cleared, prompt content is
/// carried by stdin or a private zeroed-on-drop file (never argv/environment),
/// and stdout is the only accepted output.
pub async fn run_child(
    spec: &ChildSpec,
    prompt: &[u8],
    cancellation: Cancellation,
    output: mpsc::Sender<OutputChunk>,
) -> Result<[u8; 32], ChildError> {
    let prompt_file = spec
        .prompt_file_flag
        .map(|_| PromptFile::create(&spec.scratch_dir, prompt))
        .transpose()?;
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.scratch_dir)
        .env_clear()
        .stdin(if prompt_file.is_some() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let (Some(flag), Some(file)) = (spec.prompt_file_flag, prompt_file.as_ref()) {
        command.arg(flag).arg(&file.path);
    }
    let mut child = command
        .spawn()
        .map_err(|error| ChildError::Spawn(error.to_string()))?;
    if prompt_file.is_none() {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ChildError::Stdin("missing pipe".into()))?;
        stdin
            .write_all(prompt)
            .await
            .map_err(|error| ChildError::Stdin(error.to_string()))?;
        stdin
            .shutdown()
            .await
            .map_err(|error| ChildError::Stdin(error.to_string()))?;
        drop(stdin);
    }
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ChildError::Read("missing pipe".into()))?;
    let max_output_bytes = spec.max_output_bytes;
    let max_filtered_output_bytes = spec.max_filtered_output_bytes;
    let stdout_filter = spec.stdout_filter;
    let prompt_for_filter = prompt.to_vec();
    let reader = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let mut transcript = Vec::new();
        loop {
            let count = stdout
                .read(&mut buffer)
                .await
                .map_err(|error| ChildError::Read(error.to_string()))?;
            if count == 0 {
                break;
            }
            if transcript
                .len()
                .checked_add(count)
                .is_none_or(|size| size > max_output_bytes)
            {
                return Err(ChildError::OutputLimit);
            }
            transcript.extend_from_slice(&buffer[..count]);
        }
        let filtered = match stdout_filter {
            StdoutFilter::Raw => transcript,
            StdoutFilter::PinnedLlamaCliV1 => {
                filter_pinned_llama_cli_transcript(&transcript, &prompt_for_filter)?
            }
        };
        if filtered.len() > max_filtered_output_bytes {
            return Err(ChildError::OutputLimit);
        }
        if std::str::from_utf8(&filtered).is_err() {
            return Err(ChildError::InvalidUtf8);
        }
        let mut published = Vec::with_capacity(filtered.len());
        let mut sequence = 0_u64;
        for chunk in filtered.chunks(4096) {
            published.extend_from_slice(chunk);
            sequence = sequence.saturating_add(1);
            output
                .send(OutputChunk {
                    sequence,
                    bytes: chunk.to_vec(),
                    incremental_root: *blake3::hash(&published).as_bytes(),
                })
                .await
                .map_err(|_| ChildError::StreamClosed)?;
        }
        Ok(*blake3::hash(&published).as_bytes())
    });
    tokio::select! {
        status = child.wait() => {
            let status = status.map_err(|error| ChildError::Read(error.to_string()))?;
            if !status.success() {
                reader.abort();
                return Err(ChildError::Crash(status.code()));
            }
            reader.await.map_err(|error| ChildError::Read(error.to_string()))?
        }
        () = cancellation.cancelled() => {
            let grace = tokio::time::sleep(spec.cancel_grace);
            tokio::pin!(grace);
            tokio::select! {
                _ = child.wait() => {},
                () = &mut grace => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                }
            }
            reader.abort();
            Err(ChildError::Cancelled)
        }
        () = tokio::time::sleep(spec.timeout) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            reader.abort();
            Err(ChildError::Timeout)
        }
    }
}

#[must_use]
pub fn private_child_spec(
    program: &Path,
    args: Vec<String>,
    scratch_dir: &Path,
    timeout_ms: u64,
    grace_ms: u64,
    max_output_bytes: usize,
) -> ChildSpec {
    ChildSpec {
        program: program.to_owned(),
        args,
        scratch_dir: scratch_dir.to_owned(),
        timeout: Duration::from_millis(timeout_ms),
        cancel_grace: Duration::from_millis(grace_ms),
        max_output_bytes,
        max_filtered_output_bytes: max_output_bytes,
        stdout_filter: StdoutFilter::Raw,
        prompt_file_flag: None,
    }
}

#[must_use]
pub fn private_file_prompt_child_spec(
    program: &Path,
    args: Vec<String>,
    scratch_dir: &Path,
    timeout_ms: u64,
    grace_ms: u64,
    max_output_bytes: usize,
    prompt_file_flag: &'static str,
) -> ChildSpec {
    let mut spec = private_child_spec(
        program,
        args,
        scratch_dir,
        timeout_ms,
        grace_ms,
        max_output_bytes,
    );
    spec.prompt_file_flag = Some(prompt_file_flag);
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::scheduler::Cancellation;

    #[cfg(windows)]
    fn command(script: &str) -> (PathBuf, Vec<String>) {
        (
            PathBuf::from(r"C:\Windows\System32\cmd.exe"),
            vec!["/D".into(), "/Q".into(), "/C".into(), script.into()],
        )
    }
    #[cfg(unix)]
    fn command(script: &str) -> (PathBuf, Vec<String>) {
        (PathBuf::from("/bin/sh"), vec!["-c".into(), script.into()])
    }

    async fn execute(
        script: &str,
        timeout_ms: u64,
        cancellation: Cancellation,
    ) -> (Result<[u8; 32], ChildError>, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let (program, args) = command(script);
        let spec = private_child_spec(&program, args, directory.path(), timeout_ms, 20, 1024);
        let (sender, mut receiver) = mpsc::channel::<OutputChunk>(8);
        let collector = tokio::spawn(async move {
            let mut bytes = Vec::new();
            while let Some(chunk) = receiver.recv().await {
                bytes.extend_from_slice(&chunk.bytes);
            }
            bytes
        });
        let result = run_child(&spec, b"private prompt", cancellation, sender).await;
        (result, collector.await.unwrap())
    }

    #[test]
    fn pinned_llama_transcript_filter_strips_ui_and_rejects_ambiguity() {
        let prompt = b"private prompt";
        let clean = b"\r\nLoading model... \r\n\
            banner\r\n\r\n> private prompt\r\n\r\n\
            resilient\r\n\r\nExiting...\r\n";
        assert_eq!(
            filter_pinned_llama_cli_transcript(clean, prompt).unwrap(),
            b"resilient"
        );

        let missing_suffix = b"\r\nLoading model... \r\n\
            banner\r\n\r\n> private prompt\r\n\r\nresilient";
        assert_eq!(
            filter_pinned_llama_cli_transcript(missing_suffix, prompt),
            Err(ChildError::TranscriptFraming)
        );

        let duplicate_delimiter = b"\r\nLoading model... \r\n\
            banner\r\n\r\n> private prompt\r\n\r\n\
            first\r\n> private prompt\r\n\r\nsecond\r\n\r\nExiting...\r\n";
        assert_eq!(
            filter_pinned_llama_cli_transcript(duplicate_delimiter, prompt),
            Err(ChildError::TranscriptFraming)
        );

        let echoed_prompt = b"\r\nLoading model... \r\n\
            banner\r\n\r\n> private prompt\r\n\r\n\
            private prompt\r\n\r\nExiting...\r\n";
        assert_eq!(
            filter_pinned_llama_cli_transcript(echoed_prompt, prompt),
            Err(ChildError::TranscriptFraming)
        );
    }

    #[test]
    fn private_prompt_file_is_not_content_bearing_argv_and_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path;
        {
            let prompt = PromptFile::create(directory.path(), b"private prompt").unwrap();
            path = prompt.path.clone();
            assert_eq!(fs::read(&path).unwrap(), b"private prompt");
            assert!(!path.to_string_lossy().contains("private prompt"));
        }
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn streams_stdin_without_argv_and_reports_crash() {
        #[cfg(windows)]
        let echo = r"C:\Windows\System32\more.com";
        #[cfg(unix)]
        let echo = "cat";
        let (result, output) = execute(echo, 1_000, Cancellation::new()).await;
        assert!(result.is_ok());
        #[cfg(windows)]
        assert_eq!(output, b"private prompt\r\n");
        #[cfg(unix)]
        assert_eq!(output, b"private prompt");

        #[cfg(windows)]
        let crash = "exit /b 7";
        #[cfg(unix)]
        let crash = "exit 7";
        let (result, _) = execute(crash, 1_000, Cancellation::new()).await;
        assert_eq!(result, Err(ChildError::Crash(Some(7))));
    }

    #[tokio::test]
    async fn cancellation_and_hang_are_bounded() {
        #[cfg(windows)]
        let hang = r"C:\Windows\System32\ping.exe -n 20 127.0.0.1 >nul";
        #[cfg(unix)]
        let hang = "sleep 20";
        let cancellation = Cancellation::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(15)).await;
            trigger.cancel();
        });
        let (cancelled, _) = execute(hang, 2_000, cancellation).await;
        assert_eq!(cancelled, Err(ChildError::Cancelled));
        let (timed_out, _) = execute(hang, 20, Cancellation::new()).await;
        assert_eq!(timed_out, Err(ChildError::Timeout));
    }
}
