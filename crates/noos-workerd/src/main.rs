//! `noos-workerd` legacy jobs and private Bonsai protocol-v2 executor.

use noos_workerd::config::{self, ExecutorConfig};
use noos_workerd::executor::api::{router, ApiState};
use noos_workerd::executor::bootstrap::load_and_verify_executor_bootstrap;
use noos_workerd::executor::reconstruction::reconstruct_if_absent;
use noos_workerd::executor::residency::{verify_cold_load, Residency, ResidencyState};
use noos_workerd::executor::scheduler::Cancellation;
use noos_workerd::executor::security::SidecarEndpoint;
use noos_workerd::runtime;
use noos_workerd::runtime::llama_cpp::LlamaCppAdapter;
use noos_workerd::runtime::process::run_child;
use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tokio::sync::mpsc;

const HELP: &str = "\
noos-workerd — private Bonsai executor

USAGE:
  noos-workerd legacy --config <path> [--queue <path>]
  noos-workerd serve|inspect|prefetch|drain --config <path>
  noos-workerd --help | --version

Legacy Hearth/NEL line jobs are available only through the explicit `legacy`
mode. Protocol-v2 configuration is strict and has no production defaults.
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Legacy,
    Serve,
    Inspect,
    Prefetch,
    Drain,
}

struct Args {
    mode: Mode,
    config: PathBuf,
    queue: Option<PathBuf>,
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("noos-workerd: {message}");
    eprintln!("run `noos-workerd --help` for usage");
    ExitCode::from(2)
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mode = match args.first().map(String::as_str) {
        Some("legacy") => Mode::Legacy,
        Some("serve") => Mode::Serve,
        Some("inspect") => Mode::Inspect,
        Some("prefetch") => Mode::Prefetch,
        Some("drain") => Mode::Drain,
        Some(other) => return Err(format!("unknown mode `{other}`")),
        None => return Err("an explicit mode is required".into()),
    };
    let mut config = None;
    let mut queue = None;
    let mut index = 1_usize;
    while let Some(flag) = args.get(index) {
        index = index.saturating_add(1);
        let value = args
            .get(index)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        index = index.saturating_add(1);
        match flag.as_str() {
            "--config" if config.is_none() => config = Some(PathBuf::from(value)),
            "--queue" if mode == Mode::Legacy && queue.is_none() => {
                queue = Some(PathBuf::from(value));
            }
            "--queue" => return Err("--queue is legacy-only".into()),
            other => return Err(format!("unknown or duplicate option `{other}`")),
        }
    }
    Ok(Args {
        mode,
        config: config.ok_or_else(|| "--config is required".to_owned())?,
        queue,
    })
}

fn load_v2(path: &Path) -> Result<ExecutorConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    ExecutorConfig::parse(&text).map_err(|error| format!("{}: {error}", path.display()))
}

fn run_legacy(path: &Path, queue_path: Option<&Path>) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let config = config::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match queue_path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read queue {}: {error}", path.display()))?;
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            let pending = runtime::count_job_lines(&lines);
            runtime::run(&config, lines.into_iter().map(Ok), Some(pending), &mut out)
                .map_err(|error| error.to_string())
        }
        None => {
            let stdin = std::io::stdin();
            runtime::run(&config, stdin.lock().lines(), None, &mut out)
                .map_err(|error| error.to_string())
        }
    }
}

async fn prepare(config: &ExecutorConfig) -> Result<Residency, String> {
    std::fs::create_dir_all(&config.worker.scratch_dir)
        .map_err(|error| format!("cannot create runtime scratch: {error}"))?;
    let bootstrap =
        load_and_verify_executor_bootstrap(config).map_err(|error| error.to_string())?;
    let mut residency = Residency::default();
    let reconstruction = reconstruct_if_absent(config, &bootstrap, &mut residency)
        .map_err(|error| error.to_string())?;
    eprintln!(
        "{}",
        serde_json::to_string(&reconstruction).map_err(|error| error.to_string())?
    );
    verify_cold_load(config, &mut residency, &bootstrap).map_err(|error| error.to_string())?;
    residency
        .transition(ResidencyState::Warming)
        .map_err(|error| error.to_string())?;
    let adapter = LlamaCppAdapter::new(
        config.scheduler.max_context_tokens,
        config.scheduler.max_output_tokens,
    );
    let spec = adapter
        .child_spec(config, &[1], 1)
        .map_err(|error| error.to_string())?;
    let (sender, mut receiver) = mpsc::channel(16);
    let drain = tokio::spawn(async move { while receiver.recv().await.is_some() {} });
    let result = run_child(
        &spec,
        b"Reply with exactly: OK",
        Cancellation::new(),
        sender,
    )
    .await;
    let _ = drain.await;
    result.map_err(|error| error.to_string())?;
    residency
        .transition(ResidencyState::Ready)
        .map_err(|error| error.to_string())?;
    Ok(residency)
}

async fn serve(config: ExecutorConfig) -> Result<(), String> {
    let residency = prepare(&config).await?;
    let endpoint =
        SidecarEndpoint::parse(&config.worker.listen).map_err(|error| error.to_string())?;
    let drain_file = config.worker.drain_file.clone();
    let state = ApiState::new(config, residency)?;
    let shutdown_state = state.clone();
    let shutdown = async move {
        loop {
            if drain_file.exists() {
                shutdown_state.scheduler.drain();
                if let Ok(mut residency) = shutdown_state.residency.write() {
                    let _ = residency.transition(ResidencyState::Draining);
                }
                while shutdown_state.scheduler.admitted() != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    };
    match endpoint {
        SidecarEndpoint::Tcp(address) => {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|error| format!("cannot bind private sidecar: {error}"))?;
            axum::serve(listener, router(state))
                .with_graceful_shutdown(shutdown)
                .await
                .map_err(|error| error.to_string())
        }
        #[cfg(unix)]
        SidecarEndpoint::Unix(path) => {
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|error| format!("cannot replace unix socket: {error}"))?;
            }
            let listener = tokio::net::UnixListener::bind(path)
                .map_err(|error| format!("cannot bind unix sidecar: {error}"))?;
            axum::serve(listener, router(state))
                .with_graceful_shutdown(shutdown)
                .await
                .map_err(|error| error.to_string())
        }
    }
}

fn inspect(config: &ExecutorConfig) -> Result<(), String> {
    let bootstrap =
        load_and_verify_executor_bootstrap(config).map_err(|error| error.to_string())?;
    let output =
        serde_json::to_string_pretty(bootstrap.summary()).map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn request_drain(config: &ExecutorConfig) -> Result<(), String> {
    if let Some(parent) = config.worker.drain_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create drain directory: {error}"))?;
    }
    std::fs::write(&config.worker.drain_file, b"DRAINING\n")
        .map_err(|error| format!("cannot write drain request: {error}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.as_slice() == ["--help"] || raw.as_slice() == ["-h"] {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if raw.as_slice() == ["--version"] {
        println!(
            "noos-workerd {} source_revision={}",
            option_env!("NOOS_RELEASE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
            option_env!("NOOS_SOURCE_REVISION").unwrap_or("UNBOUND")
        );
        return ExitCode::SUCCESS;
    }
    let args = match parse_args(&raw) {
        Ok(args) => args,
        Err(error) => return usage_error(&error),
    };
    let result = match args.mode {
        Mode::Legacy => run_legacy(&args.config, args.queue.as_deref()),
        Mode::Serve | Mode::Inspect | Mode::Prefetch | Mode::Drain => match load_v2(&args.config) {
            Err(error) => Err(error),
            Ok(config) => match args.mode {
                Mode::Serve => serve(config).await,
                Mode::Inspect => inspect(&config),
                Mode::Prefetch => prepare(&config)
                    .await
                    .map(|state| println!("READY residency={:?}", state.state())),
                Mode::Drain => request_drain(&config),
                Mode::Legacy => unreachable!(),
            },
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("noos-workerd: {error}");
            ExitCode::FAILURE
        }
    }
}
