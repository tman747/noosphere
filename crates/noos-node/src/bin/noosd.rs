//! noosd — the MindChain/NOOSPHERE reference node (identity-v1.md naming
//! law: binary `noosd`; state under the platform noosphere root).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use noos_grain::{encode_noun, Noun};
use noos_node::consensus::{NodeConfig, NodeMode};
use noos_node::genesis::{DevnetParams, GenesisSpec};
use noos_node::network::NetworkSettings;
use noos_node::rpc::{self, RpcConfig};
use noos_node::supervisor;

const DEVNET_CONTRACT_CODE_HASH: noos_node::Hash32 = [0xC0; 32];

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
    --validator            Devnet fixture validator (TEST NETWORKS ONLY):
                           installs the fixture witness set, produces blocks
                           on a fixed cadence, and drives fixture finality
                           at epoch boundaries. Refused when the loaded
                           parameters set is_test_network = false.
    --devnet-producer     Produce devnet blocks but require independently
                           gossiped fixture witness votes for finality.
    --devnet-witness <0..3>
                           Operate exactly one fixture finality witness with
                           persist-before-vote safety (TEST NETWORKS ONLY).
    --produce-interval-ms <ms>
                           Block production cadence for --validator
                           (default: 6000 = one block per devnet slot)
    --devnet-account <account-id-hex>
                           Pre-provision a zero-balance account in genesis
                           (repeatable; TEST NETWORKS ONLY)
    --devnet-governance-account <account-id-hex>
                           Use a pre-provisioned account as governance authority
                           (isolated TEST NETWORKS ONLY)
    --devnet-contract-fixture
                           Register the deterministic [0 1] Grain identity
                           contract at code hash c0...c0 (TEST NETWORKS ONLY)
    --devnet-witness-fixture
                           Install fixture witness bonds for certificate
                           verification without signing (TEST NETWORKS ONLY)
    --observer             Observer mode: transaction submission disabled
                           (explicit feature_disabled, never empty success)
    --p2p-listen <multiaddr>
                           QUIC listen address
                           (default: /ip4/127.0.0.1/udp/0/quic-v1)
    --peer <multiaddr>     Bootstrap peer (repeatable; reconnects with
                           deterministic bounded backoff)
    --no-network           Explicitly disable P2P (tests/maintenance only)
    --light                Light mode: headers + finality only
    --retention <blocks>   Chain-view retention window (0 = archive)
    --social-checkpoint <epoch:hash-hex>
                           Weak-subjectivity checkpoint. SOCIAL INPUT:
                           obtained socially, labeled, and NEVER able to
                           override locally finalized state.
    -h, --help             Print this help
    --version              Print version

The production network edge is enabled by default. Request/reply sync,
targeted body repair, transaction/header/vote gossip, snapshots and DA
substreams all use the closed eight-protocol noos-p2p surface.
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
    let mut validator = false;
    let mut devnet_producer = false;
    let mut devnet_witness: Option<usize> = None;
    let mut produce_interval_ms: u64 = 6000;
    let mut devnet_accounts: Vec<noos_node::Hash32> = Vec::new();
    let mut devnet_governance_account: Option<noos_node::Hash32> = None;
    let mut devnet_contract_fixture = false;
    let mut devnet_witness_fixture = false;
    let mut light = false;
    let mut retention: u64 = 0;
    let mut social: Option<noos_braid::CheckpointRef> = None;
    let mut network = NetworkSettings::default();

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
            "--p2p-listen" => match take("--p2p-listen").and_then(|v| v.parse().ok()) {
                Some(v) => network.listen = v,
                None => {
                    eprintln!("error: --p2p-listen expects a QUIC multiaddr");
                    return ExitCode::from(2);
                }
            },
            "--peer" => match take("--peer").and_then(|v| v.parse().ok()) {
                Some(v) => network.bootstrap.push(v),
                None => {
                    eprintln!("error: --peer expects a multiaddr");
                    return ExitCode::from(2);
                }
            },
            "--no-network" => network.enabled = false,
            "--validator" => validator = true,
            "--devnet-producer" => devnet_producer = true,
            "--devnet-witness" => {
                match take("--devnet-witness").and_then(|value| value.parse().ok()) {
                    Some(index) if index < 4 => devnet_witness = Some(index),
                    _ => {
                        eprintln!("error: --devnet-witness expects an index from 0 through 3");
                        return ExitCode::from(2);
                    }
                }
            }
            "--produce-interval-ms" => {
                match take("--produce-interval-ms").and_then(|v| v.parse().ok()) {
                    Some(v) => produce_interval_ms = v,
                    None => {
                        eprintln!("error: --produce-interval-ms expects milliseconds");
                        return ExitCode::from(2);
                    }
                }
            }
            "--devnet-account" => {
                match take("--devnet-account").as_deref().and_then(rpc::unhex32) {
                    Some(account) => devnet_accounts.push(account),
                    None => {
                        eprintln!("error: --devnet-account expects 32-byte hex");
                        return ExitCode::from(2);
                    }
                }
            }
            "--devnet-governance-account" => {
                match take("--devnet-governance-account")
                    .as_deref()
                    .and_then(rpc::unhex32)
                {
                    Some(account) => {
                        devnet_accounts.push(account);
                        devnet_governance_account = Some(account);
                    }
                    None => {
                        eprintln!("error: --devnet-governance-account expects 32-byte hex");
                        return ExitCode::from(2);
                    }
                }
            }
            "--devnet-contract-fixture" => devnet_contract_fixture = true,
            "--devnet-witness-fixture" => devnet_witness_fixture = true,
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
    if (validator || devnet_producer || devnet_witness.is_some()) && !params.is_test_network {
        // Fixture-refusal law (plan §2.5): fixture keys never run mainnet.
        eprintln!("error: devnet validator roles require is_test_network = true");
        return ExitCode::FAILURE;
    }
    if !devnet_accounts.is_empty() && !params.is_test_network {
        eprintln!("error: --devnet-account is a devnet fixture; is_test_network = false");
        return ExitCode::FAILURE;
    }
    if devnet_governance_account.is_some() && !params.is_test_network {
        eprintln!(
            "error: --devnet-governance-account is a devnet fixture; \
             is_test_network = false"
        );
        return ExitCode::FAILURE;
    }
    if devnet_contract_fixture && !params.is_test_network {
        eprintln!(
            "error: --devnet-contract-fixture is a devnet fixture; \
             is_test_network = false"
        );
        return ExitCode::FAILURE;
    }
    if devnet_witness_fixture && !params.is_test_network {
        eprintln!(
            "error: --devnet-witness-fixture is a devnet fixture; \
             is_test_network = false"
        );
        return ExitCode::FAILURE;
    }
    let min_bond = params.min_bond_micro;
    let witness_bonds =
        if validator || devnet_producer || devnet_witness.is_some() || devnet_witness_fixture {
            match noos_node::devnet_fixture::fixture_witness_bonds(4) {
                Ok(bonds) => bonds,
                Err(e) => {
                    eprintln!("error: fixture witness set: {e}");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            Vec::new()
        };
    devnet_accounts.sort_unstable();
    devnet_accounts.dedup();
    let mut spec = GenesisSpec::devnet(params, genesis_time_ms);
    spec.extra_accounts = devnet_accounts
        .into_iter()
        .map(|account| (account, 0))
        .collect();
    if let Some(account) = devnet_governance_account {
        spec.gov_authority = account;
    }
    let contract_codes = if devnet_contract_fixture {
        let formula = match Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1)) {
            Ok(formula) => formula,
            Err(error) => {
                eprintln!("error: build devnet contract fixture: {error}");
                return ExitCode::FAILURE;
            }
        };
        BTreeMap::from([(DEVNET_CONTRACT_CODE_HASH, encode_noun(&formula))])
    } else {
        BTreeMap::new()
    };
    spec.contract_codes = contract_codes.clone();
    let cfg = NodeConfig {
        mode: if light {
            NodeMode::Light
        } else {
            NodeMode::Full
        },
        observer,
        view_retention_blocks: retention,
        contract_codes,
        social_checkpoint: social,
        network,
        witness_bonds,
        min_bond,
        devnet_fixture_finality: validator,
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
            if let Some(addr) = &handle.p2p_addr {
                println!("p2p ready at {addr}");
            }
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

    // Clock feeder + devnet production/finality driver + ctrl-c wait.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_ctrl = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || stop_ctrl.store(true, Ordering::SeqCst));
    let mut last_produce_ms: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let _ = handle.set_now(now_ms);
        if (validator || devnet_producer)
            && now_ms.saturating_sub(last_produce_ms) >= produce_interval_ms
        {
            last_produce_ms = now_ms;
            match handle.produce_block() {
                Ok(_) => {
                    if validator {
                        // Legacy one-process fixture mode remains useful for
                        // unit/dev smoke. Distributed LAN mode uses
                        // --devnet-producer plus three independent witnesses.
                        while matches!(handle.devnet_finality_tick(), Ok(true)) {}
                    }
                }
                Err(e) => eprintln!("produce: {e}"),
            }
        }
        if let Some(index) = devnet_witness {
            if let Err(error) = handle.devnet_witness_vote_tick(index) {
                eprintln!("witness vote: {error}");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(
            100.min(produce_interval_ms.max(1)),
        ));
    }
    handle.shutdown();
    ExitCode::SUCCESS
}
