//! noos-workerd — deterministic NOOSPHERE worker daemon.
//!
//! # Wire protocol (line oriented)
//!
//! Input arrives on stdin (default) or from `--queue <file>`; one command
//! per line, blank lines ignored:
//!
//! ```text
//! JOB <job_id:64hex> relay <shape> <hops:u8> <rtt_ms:u32> <direct:0|1>
//! JOB <job_id:64hex> seed  <shape> <hops:u8> <rtt_ms:u32> <direct:0|1>
//! JOB <job_id:64hex> audit <availability_bps:u16> <role> <gate:0|1>
//! SHUTDOWN
//! ```
//!
//! Shapes: `interactive replica wan_batch stateless reissueable
//! stateful_custody chorus_advisory`. Roles: `stateful_production
//! stateless_reissueable chorus_advisory`.
//!
//! `relay`/`seed` call the real hearth routing state machine
//! (`noos_hearth::route`; `seed` sets `is_seeding`); `audit` calls the real
//! hearth custody admission law (`noos_hearth::admit_custody`) and then a
//! wired NEL Freivalds verifier self-audit
//! (`noos_nel::freivalds_verify_u64`).
//!
//! Output is written to stdout, one record per line:
//!
//! ```text
//! READY pubkey=<64hex>
//! RECEIPT body=<150hex> sig=<128hex>
//! ERR malformed <reason>
//! METRIC <telemetry-v1 family>{<bounded label>} <value>
//! SHUTDOWN jobs=<n> violations=<m>
//! ```
//!
//! Receipt body layout (75 bytes):
//! `chain_id(32) || job_id(32) || class(1) || outcome(1) || result(1) ||
//! seq_le(8)`, signed with Ed25519 under the registered
//! `D-SIG-WORK-RECEIPT` domain (`NOOS/SIG/WORK_RECEIPT/V1`). Class bytes:
//! relay=1 seed=2 audit=3. Outcome bytes: 0=accepted, 1=hearth rejection,
//! 2=verifier failure. Result bytes: route codes lan_interactive=1
//! wan_replica=2 wan_batch=3 relay_fallback=4 many_source_seeding=5, a
//! stable hearth error code on outcome 1, or 1 for a clean audit.
//!
//! Every METRIC family/label pair is a row of the frozen
//! `protocol/telemetry/telemetry-v1.yaml` contract; sequence numbers start
//! at 1 and `SHUTDOWN`/EOF both terminate gracefully with exit code 0.
//!
//! # Determinism
//!
//! The daemon takes no wall clock and draws no OS randomness: identical
//! config plus identical input produce identical output bytes. The signing
//! seed comes only from the config file.

mod config;
mod hex;
mod runtime;
mod telemetry;

use std::io::BufRead as _;
use std::process::ExitCode;

const DEFAULT_CONFIG: &str = "deploy/workerd.toml";

const HELP: &str = concat!(
    "noos-workerd — deterministic NOOSPHERE worker daemon\n",
    "\n",
    "USAGE:\n",
    "  noos-workerd [--config <path>] [--queue <path>]\n",
    "  noos-workerd --help | --version\n",
    "\n",
    "OPTIONS:\n",
    "  --config <path>  TOML config (default deploy/workerd.toml)\n",
    "  --queue <path>   read the job queue from a file instead of stdin\n",
    "  --help, -h       print this protocol description and exit\n",
    "  --version        print the version and exit\n",
    "\n",
    "CONFIG (TOML):\n",
    "  [worker]\n",
    "  seed_hex     = \"<64hex>\"  Ed25519 receipt signing seed\n",
    "  chain_id_hex = \"<64hex>\"  chain the receipts bind to\n",
    "\n",
    "INPUT PROTOCOL (one command per line; blank lines ignored):\n",
    "  JOB <job_id:64hex> relay <shape> <hops> <rtt_ms> <direct:0|1>\n",
    "  JOB <job_id:64hex> seed  <shape> <hops> <rtt_ms> <direct:0|1>\n",
    "  JOB <job_id:64hex> audit <availability_bps> <role> <gate:0|1>\n",
    "  SHUTDOWN\n",
    "  shapes: interactive replica wan_batch stateless reissueable\n",
    "          stateful_custody chorus_advisory\n",
    "  roles:  stateful_production stateless_reissueable chorus_advisory\n",
    "\n",
    "OUTPUT PROTOCOL (stdout, line oriented):\n",
    "  READY pubkey=<64hex>\n",
    "  RECEIPT body=<150hex> sig=<128hex>\n",
    "    body = chain_id(32) || job_id(32) || class(1) || outcome(1) ||\n",
    "           result(1) || seq_le(8)\n",
    "    sig  = Ed25519 under NOOS/SIG/WORK_RECEIPT/V1 (D-SIG-WORK-RECEIPT)\n",
    "    class: relay=1 seed=2 audit=3\n",
    "    outcome: 0=accepted 1=hearth_rejected 2=verifier_failed\n",
    "    result: route lan_interactive=1 wan_replica=2 wan_batch=3\n",
    "            relay_fallback=4 many_source_seeding=5; hearth error code\n",
    "            on outcome 1; audit ok=1\n",
    "  ERR malformed <reason>\n",
    "  METRIC <telemetry-v1 family>{<bounded label>} <value>\n",
    "  SHUTDOWN jobs=<n> violations=<m>\n",
    "\n",
    "DETERMINISM: no wall clock, no OS randomness; identical config and\n",
    "input produce identical output bytes. EOF is a graceful SHUTDOWN.\n",
);

fn usage_error(message: &str) -> ExitCode {
    eprintln!("noos-workerd: {message}");
    eprintln!("run `noos-workerd --help` for the protocol description");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path = DEFAULT_CONFIG.to_owned();
    let mut queue_path: Option<String> = None;
    let mut index = 0_usize;
    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("noos-workerd {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--config" => {
                index = index.saturating_add(1);
                let Some(value) = args.get(index) else {
                    return usage_error("--config requires a path");
                };
                config_path.clone_from(value);
            }
            "--queue" => {
                index = index.saturating_add(1);
                let Some(value) = args.get(index) else {
                    return usage_error("--queue requires a path");
                };
                queue_path = Some(value.clone());
            }
            other => return usage_error(&format!("unknown flag `{other}`")),
        }
        index = index.saturating_add(1);
    }

    let config_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("noos-workerd: cannot read config {config_path}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = match config::parse(&config_text) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("noos-workerd: {config_path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let result = match queue_path {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(text) => {
                let lines: Vec<String> = text.lines().map(str::to_owned).collect();
                let pending = runtime::count_job_lines(&lines);
                runtime::run(&cfg, lines.into_iter().map(Ok), Some(pending), &mut out)
            }
            Err(err) => {
                eprintln!("noos-workerd: cannot read queue {path}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            let stdin = std::io::stdin();
            runtime::run(&cfg, stdin.lock().lines(), None, &mut out)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("noos-workerd: {err}");
            ExitCode::FAILURE
        }
    }
}
