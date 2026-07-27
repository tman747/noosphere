//! Deterministic devnet-genesis identity and state-root inspector.
//!
//! This utility exercises the same `GenesisSpec` builder as `noosd` and emits
//! machine-readable roots for independent ceremony implementations. It is a
//! test-network inspection surface, never a production freeze or authorization.

use noos_node::genesis::{DevnetParams, GenesisSpec};
use noos_node::rpc::hex;
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_GENESIS_TIME_MS: u64 = 1_760_000_000_000;

fn run() -> Result<(), String> {
    let mut params = PathBuf::from("protocol/genesis/devnet-parameters.toml");
    let mut genesis_time_ms = DEFAULT_GENESIS_TIME_MS;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--params" => {
                params = arguments
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--params requires a path".to_owned())?;
            }
            "--genesis-time" => {
                genesis_time_ms = arguments
                    .next()
                    .ok_or_else(|| "--genesis-time requires unix milliseconds".to_owned())?
                    .parse()
                    .map_err(|_| "--genesis-time must be an unsigned integer".to_owned())?;
            }
            "-h" | "--help" => {
                println!("USAGE: noos-genesis-vector [--params <path>] [--genesis-time <ms>]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if arguments.next().is_some() {
        return Err("unexpected trailing argument".to_owned());
    }

    let parsed = DevnetParams::load(&params).map_err(|error| error.to_string())?;
    if !parsed.is_test_network {
        return Err("noos-genesis-vector refuses non-test-network parameters".to_owned());
    }
    let built = GenesisSpec::devnet(parsed, genesis_time_ms)
        .build()
        .map_err(|error| error.to_string())?;
    let roots = built.ledger.roots();
    let block_hash = built
        .header
        .block_hash()
        .map_err(|_| "cannot hash genesis block header".to_owned())?;
    let report = serde_json::json!({
        "schema": "noos/devnet-genesis-vector/v1",
        "source_revision": noos_node::SOURCE_REVISION,
        "release_version": noos_node::RELEASE_VERSION,
        "fixture_only": true,
        "production_authorized": false,
        "promotion_effect": "NONE",
        "chain_id": hex(&built.chain_id),
        "genesis_hash": hex(&built.genesis_hash),
        "genesis_block_hash": hex(block_hash.as_bytes()),
        "state_roots": {
            "notes_root": hex(&roots.notes_root),
            "nullifiers_root": hex(&roots.nullifiers_root),
            "accounts_root": hex(&roots.accounts_root),
            "objects_root": hex(&roots.objects_root),
            "receipts_root": hex(&roots.receipts_root),
            "params_root": hex(&roots.params_root),
        }
    });
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("noos-genesis-vector: {error}");
            ExitCode::from(2)
        }
    }
}
