//! noosd — the MindChain/NOOSPHERE reference node (identity-v1.md naming
//! law: binary `noosd`; state under the platform noosphere root).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use noos_node::consensus::{NodeConfig, NodeMode};
use noos_node::genesis::{DevnetParams, GenesisSpec};
use noos_node::rpc::{self, RpcConfig};
use noos_node::supervisor;

const HELP: &str = "\
noosd — MindChain (NOOSPHERE) reference node

USAGE:
    noosd [OPTIONS]

OPTIONS:
    --params <path>        Genesis parameters TOML
                           (default: protocol/genesis/devnet-parameters.toml)
    --data-dir <path>      Durable state root (default: ./noosd-data)
    --genesis-time <ms>    Genesis time origin, unix milliseconds
                           (devnet fixture; default: 1760000000000)
    --rpc <addr:port>      Operator RPC bind (loopback only;
                           default: 127.0.0.1:8632)
    --rpc-token <token>    Bearer token for the operator RPC (required to
                           serve RPC; without it RPC stays off)
    --observer             Observer mode: transaction submission disabled
                           (explicit feature_disabled, never empty success)
    --light                Light mode: headers + finality only
    --retention <blocks>   Chain-view retention window (0 = archive)
    --social-checkpoint <epoch:hash-hex>
                           Weak-subjectivity checkpoint. SOCIAL INPUT:
                           obtained socially, labeled, and NEVER able to
                           override locally finalized state.
    -h, --help             Print this help
    --version              Print version

The network edge is not yet bound (noos-p2p binding is a follow-up pass);
noosd runs as an isolated single node serving its operator RPC.
";

fn parse_social(arg: &str) -> Option<noos_braid::CheckpointRef> {
    let (epoch, hash_hex) = arg.split_once(':')?;
    let epoch = epoch.parse().ok()?;
    let checkpoint_hash = rpc::unhex32(hash_hex)?;
    Some(noos_braid::CheckpointRef {
        epoch,
        checkpoint_hash,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut params_path = PathBuf::from("protocol/genesis/devnet-parameters.toml");
    let mut data_dir = PathBuf::from("noosd-data");
    let mut genesis_time_ms: u64 = 1_760_000_000_000;
    let mut rpc_bind: SocketAddr = "127.0.0.1:8632".parse().unwrap_or_else(|_| unreachable!());
    let mut rpc_token: Option<String> = None;
    let mut observer = false;
    let mut light = false;
    let mut retention: u64 = 0;
    let mut social: Option<noos_braid::CheckpointRef> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut take = |name: &str| -> Option<String> {
            match it.next() {
                Some(v) => Some(v.clone()),
                None => {
                    eprintln!("error: {name} requires a value");
                    None
                }
            }
        };
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("noosd {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--params" => match take("--params") {
                Some(v) => params_path = PathBuf::from(v),
                None => return ExitCode::from(2),
            },
            "--data-dir" => match take("--data-dir") {
                Some(v) => data_dir = PathBuf::from(v),
                None => return ExitCode::from(2),
            },
            "--genesis-time" => match take("--genesis-time").and_then(|v| v.parse().ok()) {
                Some(v) => genesis_time_ms = v,
                None => {
                    eprintln!("error: --genesis-time expects unix milliseconds");
                    return ExitCode::from(2);
                }
            },
            "--rpc" => match take("--rpc").and_then(|v| v.parse().ok()) {
                Some(v) => rpc_bind = v,
                None => {
                    eprintln!("error: --rpc expects addr:port");
                    return ExitCode::from(2);
                }
            },
            "--rpc-token" => match take("--rpc-token") {
                Some(v) => rpc_token = Some(v),
                None => return ExitCode::from(2),
            },
            "--observer" => observer = true,
            "--light" => light = true,
            "--retention" => match take("--retention").and_then(|v| v.parse().ok()) {
                Some(v) => retention = v,
                None => {
                    eprintln!("error: --retention expects a block count");
                    return ExitCode::from(2);
                }
            },
            "--social-checkpoint" => match take("--social-checkpoint")
                .as_deref()
                .and_then(parse_social)
            {
                Some(cp) => social = Some(cp),
                None => {
                    eprintln!("error: --social-checkpoint expects <epoch:hash-hex>");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("error: unknown argument `{other}`\n\n{HELP}");
                return ExitCode::from(2);
            }
        }
    }

    let params = match DevnetParams::load(&params_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spec = GenesisSpec::devnet(params, genesis_time_ms);
    let cfg = NodeConfig {
        mode: if light {
            NodeMode::Light
        } else {
            NodeMode::Full
        },
        observer,
        view_retention_blocks: retention,
        social_checkpoint: social,
        ..NodeConfig::default()
    };

    let handle = match supervisor::start(cfg, spec, data_dir) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match handle.status() {
        Ok(status) => {
            println!(
                "noosd up: chain_id={} genesis_hash={} head={} finalized_epoch={}",
                rpc::hex(&status.chain_id),
                rpc::hex(&status.genesis_hash),
                status.head_height,
                status.finalized.epoch
            );
        }
        Err(e) => {
            eprintln!("error: consensus task failed to boot: {e}");
            return ExitCode::FAILURE;
        }
    }

    let _rpc_handle = match rpc_token {
        Some(token) => {
            let rpc_cfg = RpcConfig {
                bind: rpc_bind,
                token,
                observer,
            };
            match rpc::start(
                rpc_cfg,
                handle.consensus_tx.clone(),
                Arc::clone(&handle.metrics),
            ) {
                Ok(h) => {
                    println!("operator RPC ready at http://{}", h.addr);
                    Some(h)
                }
                Err(e) => {
                    eprintln!("error: rpc bind failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => {
            println!("operator RPC off (no --rpc-token)");
            None
        }
    };

    // Clock feeder + ctrl-c wait.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_ctrl = Arc::clone(&stop);
    let _ = ctrlc_handler(move || stop_ctrl.store(true, Ordering::SeqCst));
    while !stop.load(Ordering::SeqCst) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let _ = handle.set_now(now_ms);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    handle.shutdown();
    ExitCode::SUCCESS
}

/// Minimal ctrl-c hook without external crates: spawns a thread that waits
/// on stdin EOF as a fallback stop signal alongside process signals.
fn ctrlc_handler(f: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("noosd-stop".into())
        .spawn(move || {
            let mut sink = String::new();
            let _ = std::io::stdin().read_line(&mut sink);
            f();
        })
        .map(|_| ())
}
