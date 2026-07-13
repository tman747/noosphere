//! Deterministic in-process signed-transfer throughput benchmark.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use noos_codec::NoosEncode;
use noos_crypto::{DomainId, Keypair};
use noos_lumen::engine::AuthVerifier;
use noos_lumen::objects::{
    txid, witness_root, ActionV1, BoundedBytes, BoundedList, OptionalObject, ResourceVector,
    SignedIntentV1, TransactionV1, TransactionWitnessesV1,
};
use noos_lumen::state::{ApplyOutcome, BlockContext, NOOS_ASSET};
use noos_node::auth::{GrainContractEngine, NodeAuthVerifier, PreverifiedSignatureAuth};
use noos_node::genesis::{DevnetParams, GenesisSpec};
use serde_json::json;

const DEFAULT_TRANSACTIONS: usize = 10_000;
const DEFAULT_ACCOUNTS: usize = 1_024;
const DEFAULT_BATCH_SIZE: usize = 256;
const BENCHMARK_HEIGHT: u64 = 1;

struct Config {
    transactions: usize,
    accounts: usize,
    batch_size: usize,
    params: PathBuf,
    output: Option<PathBuf>,
    allow_debug: bool,
    preverified_signatures: bool,
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config {
        transactions: DEFAULT_TRANSACTIONS,
        accounts: DEFAULT_ACCOUNTS,
        batch_size: DEFAULT_BATCH_SIZE,
        params: PathBuf::from("protocol/genesis/devnet-parameters.toml"),
        output: None,
        allow_debug: false,
        preverified_signatures: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match argument.as_str() {
            "--transactions" => {
                config.transactions = value("--transactions")?
                    .parse()
                    .map_err(|_| "--transactions must be an integer".to_owned())?;
            }
            "--accounts" => {
                config.accounts = value("--accounts")?
                    .parse()
                    .map_err(|_| "--accounts must be an integer".to_owned())?;
            }
            "--batch-size" => {
                config.batch_size = value("--batch-size")?
                    .parse()
                    .map_err(|_| "--batch-size must be an integer".to_owned())?;
            }
            "--params" => config.params = PathBuf::from(value("--params")?),
            "--output" => config.output = Some(PathBuf::from(value("--output")?)),
            "--allow-debug" => config.allow_debug = true,
            "--preverified-signatures" => config.preverified_signatures = true,
            "-h" | "--help" => {
                return Err(
                    "usage: noos-throughput [--transactions N] [--accounts N] [--batch-size N] [--params PATH] [--output PATH] [--allow-debug] [--preverified-signatures]".to_owned(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if config.transactions == 0
        || config.transactions > 1_000_000
        || config.accounts == 0
        || config.accounts > 65_536
        || config.batch_size == 0
    {
        return Err("transactions, accounts, or batch size is out of range".to_owned());
    }
    if cfg!(debug_assertions) && !config.allow_debug {
        return Err(
            "refusing a debug-build measurement; run the benchmark with --release".to_owned(),
        );
    }
    Ok(config)
}

fn keypair(index: usize) -> Keypair {
    let mut input = [0_u8; 16];
    input[..8].copy_from_slice(&(index as u64).to_le_bytes());
    input[8..].copy_from_slice(b"NOOS/TPS");
    Keypair::from_seed(*blake3::hash(&input).as_bytes())
}

fn build_transaction(
    chain_id: [u8; 32],
    key: &Keypair,
    sequence: usize,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let account = key.public_key().into_bytes();
    let actions = [
        ActionV1::WithdrawFromAccount {
            account_id: account,
            asset_id: NOOS_ASSET,
            amount: 1,
        },
        ActionV1::DepositToAccount {
            account_id: account,
            asset_id: NOOS_ASSET,
            amount: 1,
        },
    ];
    let action_bytes = actions
        .iter()
        .map(|action| {
            BoundedBytes::new(action.encode_canonical())
                .ok_or_else(|| "action encoding exceeded bound".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let reveals = BoundedList::new(Vec::new()).ok_or_else(|| "reveal bound".to_owned())?;
    let transaction = TransactionV1 {
        chain_id,
        format_version: TransactionV1::VERSION,
        expiry_height: BENCHMARK_HEIGHT
            .checked_add(1)
            .and_then(|height| height.checked_add(sequence as u64))
            .ok_or_else(|| "expiry overflow".to_owned())?,
        fee_payer: account,
        fee_authorization: OptionalObject(None),
        resource_limits: ResourceVector {
            bytes: 4_096,
            grain_steps: 0,
            proof_units: 0,
            state_reads: 64,
            state_writes: 64,
            blob_bytes: 0,
        },
        note_inputs: BoundedList::new(Vec::new()).ok_or_else(|| "note bound".to_owned())?,
        account_inputs: BoundedList::new(vec![account])
            .ok_or_else(|| "account bound".to_owned())?,
        object_access_list: BoundedList::new(Vec::new())
            .ok_or_else(|| "access bound".to_owned())?,
        actions: BoundedList::new(action_bytes).ok_or_else(|| "action bound".to_owned())?,
        outputs: BoundedList::new(Vec::new()).ok_or_else(|| "output bound".to_owned())?,
        evidence_refs: BoundedList::new(Vec::new()).ok_or_else(|| "evidence bound".to_owned())?,
        witness_root: witness_root(&reveals),
    };
    let id = txid(&transaction);
    let signature = key
        .sign_domain(DomainId::SigTx, &[&id])
        .map_err(|error| format!("signing failed: {error:?}"))?;
    let witnesses = TransactionWitnessesV1 {
        intents: BoundedList::new(vec![SignedIntentV1 {
            tx_commitment: id,
            signer_scope: 0,
            capability_ref: noos_lumen::objects::OptionalHash32(None),
            signature_suite: 1,
            signature: BoundedBytes::new(signature.into_bytes().to_vec())
                .ok_or_else(|| "signature bound".to_owned())?,
        }])
        .ok_or_else(|| "intent bound".to_owned())?,
        lock_reveals: reveals,
    };
    Ok((transaction.encode_canonical(), witnesses.encode_canonical()))
}

fn percentile(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let index = ((ordered.len() - 1) as f64 * quantile).round() as usize;
    ordered[index]
}

fn run(config: &Config) -> Result<serde_json::Value, String> {
    let mut params = DevnetParams::load(&config.params).map_err(|error| error.to_string())?;
    if !params.is_test_network {
        return Err("benchmark requires test-network parameters".to_owned());
    }
    let keys = (0..config.accounts).map(keypair).collect::<Vec<_>>();
    params.faucet_pubkey = keys[0].public_key().into_bytes();
    params.faucet_allocation_micro = 1_000_000_000;
    let mut spec = GenesisSpec::devnet(params, 1_760_000_000_000);
    spec.extra_accounts = keys
        .iter()
        .skip(1)
        .map(|key| (key.public_key().into_bytes(), 1_000_000_000))
        .collect();
    let built = spec.build().map_err(|error| error.to_string())?;
    let mut ledger = built.ledger;

    let setup_started = Instant::now();
    let mut workload = Vec::with_capacity(config.transactions);
    let mut workload_hash = blake3::Hasher::new();
    let mut encoded_bytes = 0_u64;
    for sequence in 0..config.transactions {
        let envelope = build_transaction(built.chain_id, &keys[sequence % keys.len()], sequence)?;
        workload_hash.update(&envelope.0);
        workload_hash.update(&envelope.1);
        encoded_bytes = encoded_bytes
            .checked_add((envelope.0.len() + envelope.1.len()) as u64)
            .ok_or_else(|| "encoded byte count overflow".to_owned())?;
        workload.push(envelope);
    }
    let setup_seconds = setup_started.elapsed().as_secs_f64();

    let context = BlockContext {
        chain_id: built.chain_id,
        height: BENCHMARK_HEIGHT,
    };
    let engine = GrainContractEngine::default();
    let auth = NodeAuthVerifier;
    let preverified_auth = PreverifiedSignatureAuth;
    let auth: &dyn AuthVerifier = if config.preverified_signatures {
        &preverified_auth
    } else {
        &auth
    };
    let execution_started = Instant::now();
    let mut batch_tps = Vec::new();
    let mut applied = 0_usize;
    for batch in workload.chunks(config.batch_size) {
        let batch_started = Instant::now();
        for (transaction, witnesses) in batch {
            match ledger
                .apply_transaction(&context, transaction, witnesses, &engine, auth)
                .map_err(|reason| format!("workload transaction rejected: {reason:?}"))?
            {
                ApplyOutcome::Applied { .. } => applied += 1,
                ApplyOutcome::Failed { code, .. } => {
                    return Err(format!(
                        "workload transaction failed after reservation: {code:?}"
                    ));
                }
            }
        }
        let seconds = batch_started.elapsed().as_secs_f64();
        batch_tps.push(batch.len() as f64 / seconds);
    }
    let execution_seconds = execution_started.elapsed().as_secs_f64();
    let roots_started = Instant::now();
    let roots = ledger.roots();
    let root_seconds = roots_started.elapsed().as_secs_f64();
    let state_seconds = execution_seconds + root_seconds;
    let logical_cpus = std::thread::available_parallelism().map_or(1, usize::from);

    Ok(json!({
        "schema": "noos/deterministic-throughput-benchmark/v1",
        "workload": {
            "kind": "signed-self-transfer",
            "transactions": config.transactions,
            "accounts": config.accounts,
            "batch_size": config.batch_size,
            "encoded_bytes": encoded_bytes.to_string(),
            "workload_blake3": workload_hash.finalize().to_hex().to_string(),
            "contention": "transactions are striped deterministically across fee-payer accounts",
        },
        "result": {
            "applied": applied,
            "failed": 0,
            "setup_seconds": setup_seconds,
            "execution_seconds": execution_seconds,
            "root_materialization_seconds": root_seconds,
            "state_transition_seconds": state_seconds,
            "execution_tps": config.transactions as f64 / execution_seconds,
            "state_transition_tps": config.transactions as f64 / state_seconds,
            "encoded_megabytes_per_second": encoded_bytes as f64 / state_seconds / 1_000_000.0,
            "batch_tps": {
                "min": batch_tps.iter().copied().fold(f64::INFINITY, f64::min),
                "median": percentile(&batch_tps, 0.5),
                "p95": percentile(&batch_tps, 0.95),
                "max": batch_tps.iter().copied().fold(0.0, f64::max),
            },
        },
        "state_commitment": {
            "notes_root": hex(&roots.notes_root),
            "nullifiers_root": hex(&roots.nullifiers_root),
            "accounts_root": hex(&roots.accounts_root),
            "objects_root": hex(&roots.objects_root),
            "receipts_root": hex(&roots.receipts_root),
            "params_root": hex(&roots.params_root),
        },
        "environment": {
            "release_build": !cfg!(debug_assertions),
            "logical_cpus": logical_cpus,
            "target_arch": std::env::consts::ARCH,
            "target_os": std::env::consts::OS,
            "node_version": env!("CARGO_PKG_VERSION"),
            "authorization": if config.preverified_signatures { "mempool-preverified-signatures" } else { "ed25519-production" },
            "scope": "single-process deterministic state execution; excludes consensus, networking, persistence, and indexer",
        },
    }))
}

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("RESULT noos_throughput=FAIL reason={error}");
            return ExitCode::from(2);
        }
    };
    match run(&config) {
        Ok(report) => {
            let encoded = match serde_json::to_string_pretty(&report) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("RESULT noos_throughput=FAIL reason={error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Some(path) = &config.output {
                if let Some(parent) = path.parent() {
                    if let Err(error) = std::fs::create_dir_all(parent) {
                        eprintln!("RESULT noos_throughput=FAIL reason={error}");
                        return ExitCode::FAILURE;
                    }
                }
                if let Err(error) = std::fs::write(path, format!("{encoded}\n")) {
                    eprintln!("RESULT noos_throughput=FAIL reason={error}");
                    return ExitCode::FAILURE;
                }
            }
            println!("{encoded}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("RESULT noos_throughput=FAIL reason={error}");
            ExitCode::FAILURE
        }
    }
}
