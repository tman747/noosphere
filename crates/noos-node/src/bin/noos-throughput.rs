//! Deterministic in-process signed-transfer throughput benchmark.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use noos_braid::EPOCH_LENGTH;
use noos_codec::{NoosDecode, NoosEncode};
use noos_crypto::{DomainId, Keypair};
use noos_lumen::engine::AuthVerifier;
use noos_lumen::objects::{
    txid, witness_root, ActionV1, BoundedBytes, BoundedList, OptionalObject, ResourceVector,
    SignedIntentV1, TransactionV1, TransactionWitnessesV1,
};
use noos_lumen::state::{ApplyOutcome, BlockContext, NOOS_ASSET};
use noos_node::auth::{
    capture_authorization_snapshot, pipelined_transaction_prechecks, GrainContractEngine,
    NodeAuthVerifier, PreverifiedSignatureAuth, TransactionPrecheck,
};
use noos_node::consensus::{NodeConfig, NodeCore};
use noos_node::genesis::{BuiltGenesis, DevnetParams, GenesisSpec};
use noos_node::metrics::Metrics;
use noos_node::store_port::InProcStore;
use serde_json::json;

const DEFAULT_TRANSACTIONS: usize = 10_000;
const DEFAULT_ACCOUNTS: usize = 1_024;
const DEFAULT_BATCH_SIZE: usize = 256;
const DEFAULT_BLOCKS: usize = 1;
const BENCHMARK_HEIGHT: u64 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pipeline {
    State,
    DurableBlock,
    InternalAccounting,
}

struct Config {
    transactions: usize,
    accounts: usize,
    batch_size: usize,
    blocks: usize,
    finalize: bool,
    params: PathBuf,
    output: Option<PathBuf>,
    allow_debug: bool,
    preverified_signatures: bool,
    threads: Option<usize>,
    pipeline: Pipeline,
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config {
        transactions: DEFAULT_TRANSACTIONS,
        accounts: DEFAULT_ACCOUNTS,
        batch_size: DEFAULT_BATCH_SIZE,
        blocks: DEFAULT_BLOCKS,
        finalize: false,
        params: PathBuf::from("protocol/genesis/devnet-parameters.toml"),
        output: None,
        allow_debug: false,
        preverified_signatures: false,
        threads: None,
        pipeline: Pipeline::State,
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
            "--blocks" => {
                config.blocks = value("--blocks")?
                    .parse()
                    .map_err(|_| "--blocks must be an integer".to_owned())?;
            }
            "--params" => config.params = PathBuf::from(value("--params")?),
            "--output" => config.output = Some(PathBuf::from(value("--output")?)),
            "--allow-debug" => config.allow_debug = true,
            "--preverified-signatures" => config.preverified_signatures = true,
            "--finalize" => config.finalize = true,
            "--threads" => {
                config.threads = Some(
                    value("--threads")?
                        .parse()
                        .map_err(|_| "--threads must be an integer".to_owned())?,
                );
            }
            "--pipeline" => {
                config.pipeline = match value("--pipeline")?.as_str() {
                    "state" => Pipeline::State,
                    "durable-block" => Pipeline::DurableBlock,
                    "internal-accounting" => Pipeline::InternalAccounting,
                    _ => {
                        return Err(
                            "--pipeline must be state, durable-block, or internal-accounting"
                                .to_owned(),
                        );
                    }
                };
            }
            "-h" | "--help" => {
                return Err(
                    "usage: noos-throughput [--pipeline state|durable-block|internal-accounting] [--transactions N] [--blocks N] [--finalize] [--accounts N] [--batch-size N] [--threads N] [--params PATH] [--output PATH] [--allow-debug] [--preverified-signatures]".to_owned(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if config.accounts < 2
        || config.accounts > 65_536
        || config.batch_size == 0
        || config
            .threads
            .is_some_and(|threads| threads == 0 || threads > 256)
    {
        return Err("accounts, batch size, or thread count is out of range".to_owned());
    }
    match config.pipeline {
        Pipeline::InternalAccounting => {
            let equivalents = u64::try_from(config.transactions)
                .map_err(|_| "internal equivalent count exceeds u64".to_owned())?;
            let workers = config
                .threads
                .unwrap_or_else(|| thread::available_parallelism().map_or(1, usize::from));
            let accounts = u64::try_from(config.accounts)
                .map_err(|_| "internal account count exceeds u64".to_owned())?;
            if equivalents < accounts
                || equivalents > 16_000_000_000
                || equivalents % accounts != 0
                || !config.accounts.is_power_of_two()
                || equivalents / accounts < workers as u64
                || config.blocks != 1
                || config.finalize
                || config.preverified_signatures
            {
                return Err(
                    "internal-accounting requires a power-of-two account count, a whole number of account cycles, at least one cycle per worker, at most 16 billion equivalents, one block, no finalization, and no signature mode"
                        .to_owned(),
                );
            }
        }
        Pipeline::State | Pipeline::DurableBlock => {
            let total_transactions = config.transactions.checked_mul(config.blocks);
            if config.transactions == 0
                || config.transactions > 1_000_000
                || config.blocks == 0
                || config.blocks > 8
                || total_transactions.is_none_or(|total| total > 2_000_000)
                || config.threads.is_some()
            {
                return Err(
                    "transactions, blocks, or thread configuration is out of range".to_owned(),
                );
            }
            if config.pipeline == Pipeline::State && (config.blocks != 1 || config.finalize) {
                return Err(
                    "--blocks and --finalize are available only for the durable-block pipeline"
                        .to_owned(),
                );
            }
        }
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
    recipient: [u8; 32],
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
            account_id: recipient,
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
            bytes: 600,
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

struct KernelPartial {
    deltas: Vec<i64>,
    audit_xor: u64,
    audit_sum: u64,
    processed: u64,
}

#[inline(always)]
fn kernel_mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn run_internal_accounting(config: &Config) -> Result<serde_json::Value, String> {
    const INITIAL_BALANCE: u64 = 1_000_000_000_000;
    let equivalents = u64::try_from(config.transactions)
        .map_err(|_| "internal equivalent count exceeds u64".to_owned())?;
    let account_count = u64::try_from(config.accounts)
        .map_err(|_| "internal account count exceeds u64".to_owned())?;
    let logical_cpus = thread::available_parallelism().map_or(1, usize::from);
    let workers = config.threads.unwrap_or(logical_cpus);
    let cycles = equivalents / account_count;
    let base_cycles = cycles / workers as u64;
    let extra_cycles = cycles % workers as u64;
    let account_mask = config.accounts - 1;

    let started = Instant::now();
    let partials = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let worker = worker as u64;
            let worker_cycles = base_cycles + u64::from(worker < extra_cycles);
            let start_cycle = worker
                .checked_mul(base_cycles)
                .and_then(|value| value.checked_add(worker.min(extra_cycles)))
                .ok_or_else(|| "internal worker range overflow".to_owned())?;
            let start = start_cycle
                .checked_mul(account_count)
                .ok_or_else(|| "internal worker start overflow".to_owned())?;
            let end = start
                .checked_add(
                    worker_cycles
                        .checked_mul(account_count)
                        .ok_or_else(|| "internal worker length overflow".to_owned())?,
                )
                .ok_or_else(|| "internal worker end overflow".to_owned())?;
            handles.push(scope.spawn(move || {
                let mut deltas = vec![0_i64; config.accounts];
                let mut audit_xor = 0_u64;
                let mut audit_sum = 0_u64;
                for sequence in start..end {
                    let sender = sequence as usize & account_mask;
                    let recipient = (sender + 1) & account_mask;
                    let debit = deltas[sender].wrapping_sub(1);
                    deltas[sender] = debit;
                    let credit = deltas[recipient].wrapping_add(1);
                    deltas[recipient] = credit;
                    let marker = kernel_mix(
                        sequence
                            ^ ((sender as u64) << 32)
                            ^ (debit as u64).rotate_left(11)
                            ^ (credit as u64).rotate_left(29),
                    );
                    audit_xor ^= marker;
                    audit_sum = audit_sum.wrapping_add(marker.rotate_left((sequence & 63) as u32));
                }
                std::hint::black_box(KernelPartial {
                    deltas,
                    audit_xor,
                    audit_sum,
                    processed: end - start,
                })
            }));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "internal accounting worker panicked".to_owned())
            })
            .collect::<Result<Vec<_>, String>>()
    })?;
    let execution_seconds = started.elapsed().as_secs_f64();
    if execution_seconds <= 0.0 {
        return Err("internal accounting timer did not advance".to_owned());
    }

    let mut deltas = vec![0_i64; config.accounts];
    let mut audit_xor = 0_u64;
    let mut audit_sum = 0_u64;
    let mut processed = 0_u64;
    for partial in partials {
        processed = processed
            .checked_add(partial.processed)
            .ok_or_else(|| "internal processed count overflow".to_owned())?;
        audit_xor ^= partial.audit_xor;
        audit_sum = audit_sum.wrapping_add(partial.audit_sum);
        for (combined, delta) in deltas.iter_mut().zip(partial.deltas) {
            *combined = combined
                .checked_add(delta)
                .ok_or_else(|| "internal account delta overflow".to_owned())?;
        }
    }
    if processed != equivalents {
        return Err(format!(
            "internal accounting processed {processed} of {equivalents} equivalents"
        ));
    }
    let total_delta = deltas.iter().map(|delta| i128::from(*delta)).sum::<i128>();
    let all_account_deltas_zero = deltas.iter().all(|delta| *delta == 0);
    if total_delta != 0 || !all_account_deltas_zero {
        return Err("internal accounting conservation invariant failed".to_owned());
    }

    let mut state_hasher = blake3::Hasher::new();
    state_hasher.update(b"NOOS/INTERNAL-ACCOUNTING-STATE/V1");
    state_hasher.update(&equivalents.to_le_bytes());
    state_hasher.update(&account_count.to_le_bytes());
    state_hasher.update(&audit_xor.to_le_bytes());
    state_hasher.update(&audit_sum.to_le_bytes());
    for (index, delta) in deltas.iter().enumerate() {
        let final_balance = if *delta >= 0 {
            INITIAL_BALANCE.checked_add(*delta as u64)
        } else {
            INITIAL_BALANCE.checked_sub(delta.unsigned_abs())
        }
        .ok_or_else(|| "internal final balance overflow".to_owned())?;
        state_hasher.update(&(index as u64).to_le_bytes());
        state_hasher.update(&final_balance.to_le_bytes());
    }
    let state_commitment = *state_hasher.finalize().as_bytes();

    let mut workload_hasher = blake3::Hasher::new();
    workload_hasher.update(b"NOOS/INTERNAL-ACCOUNTING-WORKLOAD/V1");
    workload_hasher.update(&equivalents.to_le_bytes());
    workload_hasher.update(&account_count.to_le_bytes());
    workload_hasher.update(&(workers as u64).to_le_bytes());
    workload_hasher.update(&INITIAL_BALANCE.to_le_bytes());
    let workload_hash = workload_hasher.finalize().to_hex().to_string();

    Ok(json!({
        "schema": "noos/internal-transfer-equivalent-benchmark/v1",
        "metric": "logical_transfer_equivalents_per_second",
        "claim": {
            "network_tps": false,
            "protocol_transactions": false,
            "label": "internal deterministic accounting-kernel throughput",
            "included": [
                "one signed 64-bit debit and one signed 64-bit credit per logical equivalent",
                "per-equivalent deterministic audit mixing",
                "parallel worker launch and join",
                "exact worker reduction, conservation verification, and final BLAKE3 state commitment"
            ],
            "excluded": [
                "canonical transaction encoding and decoding",
                "signatures, authorization, fees, receipts, and sparse-Merkle updates",
                "mempool, consensus, data availability, persistence, networking, and indexer"
            ]
        },
        "workload": {
            "kind": "deterministic-netted-transfer-accounting",
            "logical_transfer_equivalents": equivalents,
            "accounts": config.accounts,
            "workers": workers,
            "amount_per_equivalent": 1,
            "initial_balance_per_account": INITIAL_BALANCE.to_string(),
            "cycles": cycles,
            "workload_blake3": workload_hash,
            "definition": "each logical equivalent executes one debit and one credit against worker-local signed account deltas; complete deterministic account cycles are reduced exactly before commitment"
        },
        "result": {
            "processed": processed,
            "failed": 0,
            "execution_seconds": execution_seconds,
            "logical_transfer_equivalents_per_second": equivalents as f64 / execution_seconds,
            "conservation_verified": true,
            "all_account_deltas_zero": all_account_deltas_zero,
            "total_account_delta": total_delta.to_string(),
            "audit_xor": format!("{audit_xor:016x}"),
            "audit_sum": format!("{audit_sum:016x}")
        },
        "state_commitment": {
            "kernel_root": hex(&state_commitment)
        },
        "environment": {
            "release_build": !cfg!(debug_assertions),
            "logical_cpus": logical_cpus,
            "worker_threads": workers,
            "target_arch": std::env::consts::ARCH,
            "target_os": std::env::consts::OS,
            "node_version": env!("CARGO_PKG_VERSION"),
            "authorization": "none-accounting-kernel-only",
            "scope": "single-process parallel deterministic accounting kernel; this is an internal logical transfer-equivalent metric and is not transaction, state-transition, durable-block, or network TPS"
        }
    }))
}

#[allow(clippy::too_many_arguments)]
fn run_durable_block(
    config: &Config,
    spec: &GenesisSpec,
    built: BuiltGenesis,
    workload: &[(Vec<u8>, Vec<u8>)],
    workload_hash: &str,
    encoded_bytes: u64,
    setup_seconds: f64,
) -> Result<serde_json::Value, String> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let store_root =
        std::env::temp_dir().join(format!("noos-throughput-{}-{unique}", std::process::id()));
    let importer_root = std::env::temp_dir().join(format!(
        "noos-throughput-importer-{}-{unique}",
        std::process::id()
    ));
    let importer_built = spec.build().map_err(|error| error.to_string())?;
    let importer_store = InProcStore::open(
        importer_root.clone(),
        &importer_built.chain_id,
        &importer_built.genesis_hash,
    )
    .map_err(|error| error.to_string())?;
    let store = InProcStore::open(store_root.clone(), &built.chain_id, &built.genesis_hash)
        .map_err(|error| error.to_string())?;
    let mut node_config = NodeConfig::default();
    node_config.network.enabled = false;
    node_config.devnet_fixture_finality = config.finalize;
    if config.finalize {
        node_config.witness_bonds = noos_node::devnet_fixture::fixture_witness_bonds(4)
            .map_err(|error| error.to_string())?;
        node_config.min_bond = spec.params.min_bond_micro;
    }
    let pool_bytes = usize::try_from(encoded_bytes)
        .map_err(|_| "encoded workload exceeds platform address space".to_owned())?;
    node_config.mempool.max_count = config.transactions;
    node_config.mempool.max_bytes = pool_bytes;
    node_config.mempool.per_source_pending = config.transactions.div_ceil(64);
    node_config.mempool.per_account_pending = config.transactions.div_ceil(config.accounts);
    node_config.mempool.template_byte_budget = pool_bytes;
    node_config.mempool.template_max_txs = config.transactions;
    let mut importer = NodeCore::boot(
        node_config.clone(),
        spec,
        importer_built,
        importer_store,
        Arc::new(Metrics::default()),
    )
    .map_err(|error| error.to_string())?;
    let metrics = Arc::new(Metrics::default());
    let mut core = NodeCore::boot(node_config, spec, built, store, Arc::clone(&metrics))
        .map_err(|error| error.to_string())?;

    let total_transactions = workload.len();
    let mut included_total = 0_usize;
    let mut admission_seconds = 0.0_f64;
    let mut pipeline_seconds = 0.0_f64;
    let mut import_seconds = 0.0_f64;
    let mut canonical_body_bytes = 0_u64;
    let mut compressed_da_form_bytes = 0_u64;
    let mut erasure_codeword_bytes = 0_u64;
    let mut sustained_floor_tps = f64::INFINITY;
    let mut block_samples = Vec::with_capacity(config.blocks);

    for block_index in 0..config.blocks {
        let start = block_index
            .checked_mul(config.transactions)
            .ok_or_else(|| "workload offset overflow".to_owned())?;
        let end = start
            .checked_add(config.transactions)
            .ok_or_else(|| "workload offset overflow".to_owned())?;
        let block_workload = workload
            .get(start..end)
            .ok_or_else(|| "workload does not contain the configured blocks".to_owned())?;
        let submissions = block_workload
            .iter()
            .enumerate()
            .map(|(offset, (transaction, witnesses))| {
                let source = u64::try_from(start.saturating_add(offset) % 64)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| "source id overflow".to_owned())?;
                Ok((transaction.as_slice(), witnesses.as_slice(), source))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let admission_started = Instant::now();
        let admission_results = core.submit_tx_batch(&submissions);
        for (offset, result) in admission_results.into_iter().enumerate() {
            result.map_err(|error| {
                format!(
                    "mempool admission {} failed: {error:?}",
                    start.saturating_add(offset)
                )
            })?;
        }
        let block_admission_seconds = admission_started.elapsed().as_secs_f64();
        admission_seconds += block_admission_seconds;

        let timestamp_offset = u64::try_from(block_index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .and_then(|index| index.checked_mul(6_000))
            .ok_or_else(|| "benchmark clock overflow".to_owned())?;
        core.set_now(
            spec.genesis_time_ms
                .checked_add(timestamp_offset)
                .ok_or_else(|| "benchmark clock overflow".to_owned())?,
        );
        let pipeline_started = Instant::now();
        let block = core.produce_block().map_err(|error| error.to_string())?;
        let block_pipeline_seconds = pipeline_started.elapsed().as_secs_f64();
        pipeline_seconds += block_pipeline_seconds;

        let block_shard_bytes = block
            .shards
            .iter()
            .try_fold(0_u64, |total, shard| {
                total.checked_add(shard.bytes.len() as u64)
            })
            .ok_or_else(|| "shard byte count overflow".to_owned())?;
        importer.set_now(block.header.timestamp_ms);
        let import_started = Instant::now();
        importer
            .import_block_owned(&block.header, &block.ticket, &block.claim, block.shards)
            .map_err(|error| error.to_string())?;
        let block_import_seconds = import_started.elapsed().as_secs_f64();
        import_seconds += block_import_seconds;

        let included = block.body.transactions.len();
        if included != block_workload.len() {
            return Err(format!(
                "block {} included {included} of {} admitted transactions",
                block_index.saturating_add(1),
                block_workload.len()
            ));
        }
        included_total = included_total
            .checked_add(included)
            .ok_or_else(|| "included transaction count overflow".to_owned())?;
        let block_canonical_body_bytes = u64::try_from(block.body.encode_canonical().len())
            .map_err(|_| "canonical body byte count overflow".to_owned())?;
        canonical_body_bytes = canonical_body_bytes
            .checked_add(block_canonical_body_bytes)
            .ok_or_else(|| "canonical body byte count overflow".to_owned())?;
        compressed_da_form_bytes = compressed_da_form_bytes
            .checked_add(block.claim.original_bytes)
            .ok_or_else(|| "compressed body byte count overflow".to_owned())?;
        erasure_codeword_bytes = erasure_codeword_bytes
            .checked_add(block_shard_bytes)
            .ok_or_else(|| "shard byte count overflow".to_owned())?;

        let roots = core.ledger().roots();
        if importer.ledger().roots() != roots {
            return Err(format!(
                "producer and validator state commitments diverged after block {}",
                block_index.saturating_add(1)
            ));
        }
        let producer_tps = included as f64 / block_pipeline_seconds;
        let validator_tps = included as f64 / block_import_seconds;
        sustained_floor_tps = sustained_floor_tps.min(producer_tps).min(validator_tps);
        block_samples.push(json!({
            "block": block_index.saturating_add(1),
            "height": block.header.height,
            "transactions": included,
            "admission_seconds": block_admission_seconds,
            "admission_tps": included as f64 / block_admission_seconds,
            "producer_seconds": block_pipeline_seconds,
            "producer_tps": producer_tps,
            "validator_import_seconds": block_import_seconds,
            "validator_import_tps": validator_tps,
            "canonical_body_bytes": block_canonical_body_bytes.to_string(),
            "compressed_da_form_bytes": block.claim.original_bytes.to_string(),
            "erasure_codeword_bytes": block_shard_bytes.to_string(),
        }));
    }

    let measured_roots = core.ledger().roots();
    let finality_report = if config.finalize {
        let finality_started = Instant::now();
        let target_height = EPOCH_LENGTH
            .checked_mul(2)
            .ok_or_else(|| "finality target height overflow".to_owned())?;
        while core.head().0 < target_height {
            let next_height = core
                .head()
                .0
                .checked_add(1)
                .ok_or_else(|| "finality height overflow".to_owned())?;
            let timestamp_offset = next_height
                .checked_mul(6_000)
                .ok_or_else(|| "finality clock overflow".to_owned())?;
            core.set_now(
                spec.genesis_time_ms
                    .checked_add(timestamp_offset)
                    .ok_or_else(|| "finality clock overflow".to_owned())?,
            );
            let block = core.produce_block().map_err(|error| error.to_string())?;
            importer.set_now(block.header.timestamp_ms);
            importer
                .import_block_owned(&block.header, &block.ticket, &block.claim, block.shards)
                .map_err(|error| error.to_string())?;
        }
        for round in 1..=2 {
            if !core
                .devnet_finality_tick()
                .map_err(|error| error.to_string())?
            {
                return Err(format!("producer finality round {round} did not advance"));
            }
            if !importer
                .devnet_finality_tick()
                .map_err(|error| error.to_string())?
            {
                return Err(format!("validator finality round {round} did not advance"));
            }
        }
        let finalized = core.finalized();
        if finalized != importer.finalized() || finalized.epoch < 1 {
            return Err("producer and validator finalized checkpoints diverged".to_owned());
        }
        let finalized_height = finalized
            .expected_height()
            .ok_or_else(|| "invalid finalized checkpoint height".to_owned())?;
        if u64::try_from(config.blocks)
            .map_or(true, |measured_height| measured_height > finalized_height)
        {
            return Err("measured transfer blocks are not finalized ancestors".to_owned());
        }
        for index in [0, workload.len().saturating_sub(1)] {
            let transaction = TransactionV1::decode_canonical(&workload[index].0)
                .map_err(|error| format!("finality receipt transaction decode: {error:?}"))?;
            let id = txid(&transaction);
            if core.ledger().get_receipt(&id).is_none()
                || importer.ledger().get_receipt(&id).is_none()
            {
                return Err("finalized transfer receipt is missing".to_owned());
            }
        }
        if importer.ledger().roots() != core.ledger().roots() {
            return Err("finalized producer and validator state diverged".to_owned());
        }
        json!({
            "verified": true,
            "driver": "independent-devnet-witness-fixture",
            "checkpoint_epoch": finalized.epoch,
            "checkpoint_height": finalized_height,
            "checkpoint_hash": hex(&finalized.checkpoint_hash),
            "finalized_transactions": included_total,
            "advance_seconds": finality_started.elapsed().as_secs_f64(),
            "empty_blocks_after_measurement": target_height
                .saturating_sub(u64::try_from(config.blocks).unwrap_or(0)),
        })
    } else {
        serde_json::Value::Null
    };
    let roots = core.ledger().roots();
    let durable_sequence = metrics.store_seq.load(Ordering::Relaxed);
    let logical_cpus = std::thread::available_parallelism().map_or(1, usize::from);
    let serial_end_to_end_seconds = admission_seconds + pipeline_seconds + import_seconds;
    let report = json!({
        "schema": "noos/deterministic-throughput-benchmark/v1",
        "workload": {
            "kind": "signed-transfer",
            "transactions": total_transactions,
            "transactions_per_block": config.transactions,
            "blocks": config.blocks,
            "accounts": config.accounts,
            "batch_size": config.batch_size,
            "encoded_bytes": encoded_bytes.to_string(),
            "workload_blake3": workload_hash,
            "contention": "each fee payer transfers to the next deterministic account; complete account cycles conserve every account balance before fees",
        },
        "result": {
            "applied": included_total,
            "failed": 0,
            "pending_after_block": total_transactions.saturating_sub(included_total),
            "setup_seconds": setup_seconds,
            "admission_seconds": admission_seconds,
            "admission_tps": total_transactions as f64 / admission_seconds,
            "block_pipeline_seconds": pipeline_seconds,
            "block_pipeline_tps": included_total as f64 / pipeline_seconds,
            "validator_import_seconds": import_seconds,
            "validator_import_tps": included_total as f64 / import_seconds,
            "serial_end_to_end_seconds": serial_end_to_end_seconds,
            "serial_end_to_end_tps": included_total as f64 / serial_end_to_end_seconds,
            "sustained_floor_tps": sustained_floor_tps,
            "canonical_body_bytes": canonical_body_bytes.to_string(),
            "compressed_da_form_bytes": compressed_da_form_bytes.to_string(),
            "erasure_codeword_bytes": erasure_codeword_bytes.to_string(),
            "durable_store_sequence": durable_sequence.to_string(),
            "block_samples": block_samples,
            "finality": finality_report,
        },
        "measured_state_commitment": {
            "notes_root": hex(&measured_roots.notes_root),
            "nullifiers_root": hex(&measured_roots.nullifiers_root),
            "accounts_root": hex(&measured_roots.accounts_root),
            "objects_root": hex(&measured_roots.objects_root),
            "receipts_root": hex(&measured_roots.receipts_root),
            "params_root": hex(&measured_roots.params_root),
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
            "authorization": "mempool-preverified-signatures",
            "scope": if config.finalize {
                "two independent durable node instances in one process across consecutive measured blocks, followed through the cryptographic two-epoch finality ladder; includes producer admission, execution, roots, body commitments, Reed-Solomon DA, protocol WAL fsync, RocksDB apply, validator reconstruction/import, and independent fixture-witness certificates; excludes network propagation"
            } else {
                "two independent durable node instances in one process across consecutive blocks; includes producer admission, execution, roots, body commitments, Reed-Solomon DA, protocol WAL fsync, RocksDB apply, and validator reconstruction/import; excludes network propagation and finality"
            },
        },
    });
    drop(core);
    drop(importer);
    std::fs::remove_dir_all(store_root).map_err(|error| error.to_string())?;
    std::fs::remove_dir_all(importer_root).map_err(|error| error.to_string())?;
    Ok(report)
}

fn run(config: &Config) -> Result<serde_json::Value, String> {
    if config.pipeline == Pipeline::InternalAccounting {
        return run_internal_accounting(config);
    }
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

    let setup_started = Instant::now();
    let total_transactions = config
        .transactions
        .checked_mul(config.blocks)
        .ok_or_else(|| "workload transaction count overflow".to_owned())?;
    let mut workload = Vec::with_capacity(total_transactions);
    let mut workload_hash = blake3::Hasher::new();
    let mut encoded_bytes = 0_u64;
    for sequence in 0..total_transactions {
        let sender_index = sequence % keys.len();
        let recipient_index = (sender_index + 1) % keys.len();
        let recipient = keys[recipient_index].public_key().into_bytes();
        let envelope = build_transaction(built.chain_id, &keys[sender_index], recipient, sequence)?;
        workload_hash.update(&envelope.0);
        workload_hash.update(&envelope.1);
        encoded_bytes = encoded_bytes
            .checked_add((envelope.0.len() + envelope.1.len()) as u64)
            .ok_or_else(|| "encoded byte count overflow".to_owned())?;
        workload.push(envelope);
    }
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    let workload_hash = workload_hash.finalize().to_hex().to_string();
    if config.pipeline == Pipeline::DurableBlock {
        return run_durable_block(
            config,
            &spec,
            built,
            &workload,
            &workload_hash,
            encoded_bytes,
            setup_seconds,
        );
    }
    let decode_started = Instant::now();
    let mut decoded_transactions = Vec::with_capacity(workload.len());
    let mut decoded_witnesses = Vec::with_capacity(workload.len());
    let mut encoded_lengths = Vec::with_capacity(workload.len());
    for (transaction, witnesses) in &workload {
        decoded_transactions.push(
            TransactionV1::decode_canonical(transaction)
                .map_err(|error| format!("transaction decode failed: {error:?}"))?,
        );
        decoded_witnesses.push(
            TransactionWitnessesV1::decode_canonical(witnesses)
                .map_err(|error| format!("witness decode failed: {error:?}"))?,
        );
        encoded_lengths.push(
            transaction
                .len()
                .checked_add(witnesses.len())
                .ok_or_else(|| "encoded transaction length overflow".to_owned())?,
        );
    }
    let decode_seconds = decode_started.elapsed().as_secs_f64();
    let mut ledger = built.ledger;

    let context = BlockContext {
        chain_id: built.chain_id,
        height: BENCHMARK_HEIGHT,
    };
    let engine = GrainContractEngine::default();
    let auth = NodeAuthVerifier;
    let snapshot_started = Instant::now();
    let authorization_snapshot = config
        .preverified_signatures
        .then(|| capture_authorization_snapshot(&ledger, &decoded_transactions));
    let authorization_snapshot_seconds = snapshot_started.elapsed().as_secs_f64();
    let execution_started = Instant::now();
    let mut batch_tps = Vec::new();
    let mut applied = 0_usize;
    let (execution_result, _balance_root_delta) =
        ledger.with_deferred_balance_roots(|ledger, deferred| {
            let mut execute_checks = |start: usize,
                                      checks: &[Option<TransactionPrecheck>]|
             -> Result<(), String> {
                for local_batch_start in (0..checks.len()).step_by(config.batch_size) {
                    let local_batch_end = local_batch_start
                        .saturating_add(config.batch_size)
                        .min(checks.len());
                    let batch_started = Instant::now();
                    for offset in local_batch_start..local_batch_end {
                        let index = start.saturating_add(offset);
                        let transaction = &decoded_transactions[index];
                        let witnesses = &decoded_witnesses[index];
                        let precheck = checks[offset].as_ref();
                        let signatures_unchanged = precheck
                            .zip(authorization_snapshot.as_ref())
                            .is_some_and(|(check, snapshot)| {
                                check.signatures_reusable(snapshot, ledger, deferred, transaction)
                            });
                        let preverified_auth = precheck
                            .map(|check| PreverifiedSignatureAuth::new(check.transaction_id()));
                        let verifier: &dyn AuthVerifier =
                            match (signatures_unchanged, preverified_auth.as_ref()) {
                                (true, Some(verifier)) => verifier,
                                _ => &auth,
                            };
                        match ledger
                            .apply_canonical_decoded_transaction_deferred(
                                &context,
                                transaction,
                                witnesses,
                                encoded_lengths[index],
                                &engine,
                                verifier,
                                deferred,
                            )
                            .map_err(|reason| {
                                format!("workload transaction rejected: {reason:?}")
                            })? {
                            ApplyOutcome::Applied { .. } => applied += 1,
                            ApplyOutcome::Failed { code, .. } => {
                                return Err(format!(
                                    "workload transaction failed after reservation: {code:?}"
                                ));
                            }
                        }
                    }
                    let seconds = batch_started.elapsed().as_secs_f64();
                    batch_tps
                        .push(local_batch_end.saturating_sub(local_batch_start) as f64 / seconds);
                }
                Ok(())
            };
            if let Some(snapshot) = authorization_snapshot.as_ref() {
                pipelined_transaction_prechecks(
                    snapshot,
                    &decoded_transactions,
                    &decoded_witnesses,
                    &mut execute_checks,
                )
            } else {
                let checks = vec![None; decoded_transactions.len()];
                execute_checks(0, &checks)
            }
        });
    execution_result?;
    let execution_seconds = execution_started.elapsed().as_secs_f64();
    let roots_started = Instant::now();
    let roots = ledger.roots();
    let root_seconds = roots_started.elapsed().as_secs_f64();
    let state_seconds = execution_seconds + root_seconds;
    let signed_state_seconds = authorization_snapshot_seconds + state_seconds;
    let validator_state_seconds = decode_seconds + signed_state_seconds;
    let logical_cpus = std::thread::available_parallelism().map_or(1, usize::from);

    Ok(json!({
        "schema": "noos/deterministic-throughput-benchmark/v1",
        "workload": {
            "kind": "signed-transfer",
            "transactions": config.transactions,
            "accounts": config.accounts,
            "batch_size": config.batch_size,
            "encoded_bytes": encoded_bytes.to_string(),
            "workload_blake3": workload_hash,
            "contention": "each fee payer transfers to the next deterministic account; complete account cycles conserve every account balance before fees",
        },
        "result": {
            "applied": applied,
            "failed": 0,
            "setup_seconds": setup_seconds,
            "canonical_decode_seconds": decode_seconds,
            "authorization_snapshot_seconds": authorization_snapshot_seconds,
            "execution_seconds": execution_seconds,
            "root_materialization_seconds": root_seconds,
            "state_transition_seconds": state_seconds,
            "execution_tps": config.transactions as f64 / execution_seconds,
            "state_transition_tps": config.transactions as f64 / state_seconds,
            "signed_state_transition_seconds": signed_state_seconds,
            "signed_state_transition_tps": config.transactions as f64 / signed_state_seconds,
            "validator_state_seconds": validator_state_seconds,
            "validator_state_tps": config.transactions as f64 / validator_state_seconds,
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
            "authorization": if config.preverified_signatures { "parallel-ed25519-production-precheck" } else { "sequential-ed25519-production" },
            "scope": "single-process signed-transfer validation and deterministic state execution; signed_state_transition includes production signature verification, execution, and roots; validator_state also includes canonical decoding; excludes consensus, networking, persistence, and indexer",
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
