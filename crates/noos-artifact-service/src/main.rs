use std::env;
use std::error::Error;
use std::fmt::Display;
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use noos_artifact_service::server::{router, ArtifactHttpConfig, ArtifactHttpState};
use noos_artifact_service::web_bundle::{
    export_bonsai_web_bundle, read_coordinate_selection, signing_seed_from_env,
    verify_bonsai_web_bundle, WebBundleExportConfig,
};
use noos_artifact_service::web_restore_import::{
    import_web_restored_position, ImportChainBinding, WebRestoredPositionImportConfig,
};
use noos_artifact_service::{
    repair_bonsai_position, verify_bonsai_store, BonsaiStoreSink, BONSAI_MANIFEST_ROOT_HEX,
    BONSAI_RETENTION_EPOCHS,
};
use noos_da::ArtifactEncoderV1;
use noos_store::{ArtifactStore, ArtifactStoreConfig};
use serde::Serialize;
use tokio::net::TcpListener;

const USAGE: &str = "noos-artifact-service <command>\n\
  ingest --source <gguf> --store-root <absolute-path> --consensus-root <absolute-path> --quota-bytes <u64> [--staging-root <absolute-path>] [--report <path>]\n\
  verify --store-root <absolute-path> --consensus-root <absolute-path> --quota-bytes <u64> [--staging-root <absolute-path>] [--report <path>]\n\
  repair-position --position <0..11> --source-positions <p,p,p,p,p,p,p,p> --store-root <absolute-path> --consensus-root <absolute-path> --quota-bytes <u64>\n\
        --replacement-root <absolute-path> --replacement-consensus-root <absolute-path> --replacement-quota-bytes <u64> [--replacement-staging-root <absolute-path>] [--report <path>]\n\
  serve --listen <ip:port> --store-root <absolute-path> --consensus-root <absolute-path> --quota-bytes <u64> [--staging-root <absolute-path>]\n\
        [--max-concurrency <1..64>] [--queue-capacity <0..1024>] [--per-client-rps <1..10000>]\n\
        [--max-tracked-clients <n>] [--max-request-metadata-bytes <n>] [--max-range-bytes <n>]\n\
        [--queue-wait-ms <n>] [--egress-bytes-per-second <n>] [--egress-wait-ms <n>]\n\
        [--metrics-log-seconds <1..300>] [--report <path>]\n\
  export-web-bundle --store-root <absolute-path> --consensus-root <absolute-path> --quota-bytes <u64> [--staging-root <absolute-path>]\n\
        --output-root <path> --origin <canonical-https-origin> --chain-id <hex32> --genesis-hash <hex32>\n\
        --coordinates <json-path> --host-signing-seed-env <name> --valid-from <unix-seconds> --expires-at <unix-seconds>\n\
        --license <path> --notice <path> [--report <path>]\n\
  verify-web-bundle --store-root <absolute-path> --consensus-root <absolute-path> --quota-bytes <u64> [--staging-root <absolute-path>]\n\
        --bundle-root <path> --origin <canonical-https-origin> --chain-id <hex32> --genesis-hash <hex32> [--report <path>]\n\
  import-web-restored-position --store-root <absolute-source-path> --consensus-root <absolute-path> --quota-bytes <u64> [--staging-root <absolute-path>]\n\
        --quarantine-root <absolute-path> --import-index <json-path> --position <0..11> --coordinator-public-key <hex32>\n\
        --chain-id <hex32> --genesis-hash <hex32> --artifact-id <hex32> --manifest-root <hex32>\n\
        --replacement-root <absolute-path> --replacement-consensus-root <absolute-path> --replacement-quota-bytes <u64>\n\
        [--replacement-staging-root <absolute-path>] --report <create-new-path>";

#[derive(Serialize)]
struct IngestReport<'a> {
    schema: &'static str,
    source: String,
    initial_completed_stripes: usize,
    initial_published: bool,
    verification: &'a noos_artifact_service::StoreVerificationReport,
}

#[derive(Serialize)]
struct ServeReport<'a> {
    schema: &'static str,
    listen: String,
    artifact_root: String,
    consensus_root: String,
    production_claimed: bool,
    public_internet_authorized: bool,
    upload_lane_enabled: bool,
    cors_wildcard_scope: &'static str,
    http: &'a ArtifactHttpConfig,
    verification: &'a noos_artifact_service::StoreVerificationReport,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return Err(USAGE.into());
    };
    let rest = &args[1..];
    let store_root = PathBuf::from(required(rest, "--store-root")?);
    let consensus_root = PathBuf::from(required(rest, "--consensus-root")?);
    let quota_bytes = required(rest, "--quota-bytes")?
        .parse::<u64>()
        .map_err(|error| format!("invalid --quota-bytes: {error}"))?;
    let report_path = optional(rest, "--report").map(PathBuf::from);

    let mut config = ArtifactStoreConfig::under(store_root, consensus_root, quota_bytes);
    if let Some(staging_root) = optional(rest, "--staging-root") {
        config.staging = PathBuf::from(staging_root);
    }
    match command {
        "ingest" => {
            let source_path = PathBuf::from(required(rest, "--source")?);
            let store = ArtifactStore::open(config)?;
            let mut sink = BonsaiStoreSink::new(store)?;
            let mut source = File::open(&source_path)?;
            ArtifactEncoderV1::new()?.encode(&mut source, &mut sink, BONSAI_RETENTION_EPOCHS)?;
            let initial = sink
                .initial_resume()
                .cloned()
                .ok_or("encoder did not initialize the artifact sink")?;
            let store = sink.into_store();
            let verification = verify_bonsai_store(&store)?;
            let report = IngestReport {
                schema: "noos.wwm.artifact-ingest.v1",
                source: source_path.display().to_string(),
                initial_completed_stripes: initial.completed_stripes.len(),
                initial_published: initial.published,
                verification: &verification,
            };
            emit_report(&report, report_path.as_deref())?;
        }
        "verify" => {
            let store = ArtifactStore::open(config)?;
            let report = verify_bonsai_store(&store)?;
            emit_report(&report, report_path.as_deref())?;
        }
        "repair-position" => {
            let missing_position = required(rest, "--position")?
                .parse::<u8>()
                .map_err(|error| format!("invalid --position: {error}"))?;
            let source_positions = required(rest, "--source-positions")?
                .split(',')
                .map(|value| {
                    value
                        .parse::<u8>()
                        .map_err(|error| format!("invalid --source-positions entry: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let source_store = ArtifactStore::open(config)?;
            let replacement_root = PathBuf::from(required(rest, "--replacement-root")?);
            let replacement_consensus =
                PathBuf::from(required(rest, "--replacement-consensus-root")?);
            let replacement_quota = required(rest, "--replacement-quota-bytes")?
                .parse::<u64>()
                .map_err(|error| format!("invalid --replacement-quota-bytes: {error}"))?;
            let mut replacement_config = ArtifactStoreConfig::under(
                replacement_root,
                replacement_consensus,
                replacement_quota,
            );
            if let Some(staging_root) = optional(rest, "--replacement-staging-root") {
                replacement_config.staging = PathBuf::from(staging_root);
            }
            let replacement_store = ArtifactStore::open(replacement_config)?;
            let report = repair_bonsai_position(
                &source_store,
                replacement_store,
                missing_position,
                &source_positions,
            )?;
            emit_report(&report, report_path.as_deref())?;
        }
        "export-web-bundle" => {
            let store = ArtifactStore::open(config)?;
            let coordinate_path = PathBuf::from(required(rest, "--coordinates")?);
            let coordinates = read_coordinate_selection(&coordinate_path)?;
            let signing_seed = signing_seed_from_env(&required(rest, "--host-signing-seed-env")?)?;
            let valid_from = required(rest, "--valid-from")?
                .parse::<u64>()
                .map_err(|error| format!("invalid --valid-from: {error}"))?;
            let expires_at = required(rest, "--expires-at")?
                .parse::<u64>()
                .map_err(|error| format!("invalid --expires-at: {error}"))?;
            let report = export_bonsai_web_bundle(
                &store,
                WebBundleExportConfig {
                    output_root: PathBuf::from(required(rest, "--output-root")?),
                    canonical_origin: required(rest, "--origin")?,
                    chain_id: required(rest, "--chain-id")?,
                    genesis_hash: required(rest, "--genesis-hash")?,
                    valid_from,
                    expires_at,
                    license_path: PathBuf::from(required(rest, "--license")?),
                    notice_path: PathBuf::from(required(rest, "--notice")?),
                    coordinates,
                    signing_seed,
                },
            )?;
            emit_report(&report, report_path.as_deref())?;
        }
        "verify-web-bundle" => {
            let store = ArtifactStore::open(config)?;
            let bundle_root = PathBuf::from(required(rest, "--bundle-root")?);
            let report = verify_bonsai_web_bundle(
                &store,
                &bundle_root,
                &required(rest, "--origin")?,
                &required(rest, "--chain-id")?,
                &required(rest, "--genesis-hash")?,
            )?;
            emit_report(&report, report_path.as_deref())?;
        }
        "import-web-restored-position" => {
            let target_position = required(rest, "--position")?
                .parse::<u8>()
                .map_err(|error| format!("invalid --position: {error}"))?;
            let replacement_root = PathBuf::from(required(rest, "--replacement-root")?);
            let replacement_consensus =
                PathBuf::from(required(rest, "--replacement-consensus-root")?);
            let replacement_quota = required(rest, "--replacement-quota-bytes")?
                .parse::<u64>()
                .map_err(|error| format!("invalid --replacement-quota-bytes: {error}"))?;
            let mut replacement_config = ArtifactStoreConfig::under(
                replacement_root,
                replacement_consensus,
                replacement_quota,
            );
            if let Some(staging_root) = optional(rest, "--replacement-staging-root") {
                replacement_config.staging = PathBuf::from(staging_root);
            }
            let report_path = report_path
                .ok_or("import-web-restored-position requires --report with a new path")?;
            let evidence = import_web_restored_position(WebRestoredPositionImportConfig {
                source_store: config,
                quarantine_root: PathBuf::from(required(rest, "--quarantine-root")?),
                import_index_path: PathBuf::from(required(rest, "--import-index")?),
                target_position,
                expected_coordinator_public_key: required(rest, "--coordinator-public-key")?,
                expected_chain_binding: ImportChainBinding {
                    chain_id: required(rest, "--chain-id")?,
                    genesis_hash: required(rest, "--genesis-hash")?,
                    artifact_id: required(rest, "--artifact-id")?,
                    manifest_root: required(rest, "--manifest-root")?,
                },
                replacement_store: replacement_config,
                report_path,
            })?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        "serve" => {
            let listen = required(rest, "--listen")?.parse::<SocketAddr>()?;
            let mut http = ArtifactHttpConfig::default();
            http.max_concurrent_requests =
                parsed(rest, "--max-concurrency", http.max_concurrent_requests)?;
            http.queue_capacity = parsed(rest, "--queue-capacity", http.queue_capacity)?;
            http.per_client_requests_per_second = parsed(
                rest,
                "--per-client-rps",
                http.per_client_requests_per_second,
            )?;
            http.max_tracked_clients =
                parsed(rest, "--max-tracked-clients", http.max_tracked_clients)?;
            http.max_request_metadata_bytes = parsed(
                rest,
                "--max-request-metadata-bytes",
                http.max_request_metadata_bytes,
            )?;
            http.max_range_bytes = parsed(rest, "--max-range-bytes", http.max_range_bytes)?;
            http.queue_wait_millis = parsed(rest, "--queue-wait-ms", http.queue_wait_millis)?;
            http.egress_bytes_per_second = parsed(
                rest,
                "--egress-bytes-per-second",
                http.egress_bytes_per_second,
            )?;
            http.egress_wait_millis = parsed(rest, "--egress-wait-ms", http.egress_wait_millis)?;
            http.validate()?;
            let metrics_log_seconds = parsed(rest, "--metrics-log-seconds", 10_u64)?;
            if !(1..=300).contains(&metrics_log_seconds) {
                return Err("--metrics-log-seconds must be within 1..=300".into());
            }

            let artifact_root = config.root.display().to_string();
            let consensus_root = config.consensus_root.display().to_string();
            let mut store_config = config;
            store_config.max_concurrency = u16::try_from(http.max_concurrent_requests)?;
            store_config.io_bytes_per_second = http.egress_bytes_per_second;
            let store = ArtifactStore::open(store_config)?;
            let (state, verification) = ArtifactHttpState::initialize(store, http)?;
            let listener = TcpListener::bind(listen).await?;
            let bound = listener.local_addr()?;
            let report = ServeReport {
                schema: "noos.wwm.artifact-service-startup.v1",
                listen: bound.to_string(),
                artifact_root,
                consensus_root,
                production_claimed: false,
                public_internet_authorized: false,
                upload_lane_enabled: false,
                cors_wildcard_scope: "public immutable manifest/share bytes only",
                http: state.config(),
                verification: &verification,
            };
            emit_report(&report, report_path.as_deref())?;
            eprintln!(
                "artifact service ready listen={bound} manifest_root={BONSAI_MANIFEST_ROOT_HEX}"
            );

            let metrics_state = state.clone();
            let metrics_task = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(metrics_log_seconds));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    if let Ok(line) = serde_json::to_string(&metrics_state.metrics_snapshot()) {
                        eprintln!("{line}");
                    }
                }
            });
            let service = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
            let result = axum::serve(listener, service)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await;
            metrics_task.abort();
            if let Ok(line) = serde_json::to_string(&state.metrics_snapshot()) {
                eprintln!("{line}");
            }
            result?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn required(args: &[String], flag: &str) -> Result<String, String> {
    optional(args, flag).ok_or_else(|| format!("missing {flag}\n{USAGE}"))
}

fn optional(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn parsed<T>(args: &[String], flag: &str, default: T) -> Result<T, String>
where
    T: FromStr,
    T::Err: Display,
{
    optional(args, flag).map_or(Ok(default), |value| {
        value
            .parse::<T>()
            .map_err(|error| format!("invalid {flag}: {error}"))
    })
}

fn emit_report<T: Serialize>(report: &T, path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let bytes = serde_json::to_vec_pretty(report)?;
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, &bytes)?;
        std::fs::rename(temp, path)?;
    }
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}
