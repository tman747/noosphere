use noos_mind_gateway::service::web_capacity::{
    QueueRestoreAdminRequest, SignedRestoredPositionImportIndex, WebCapacityConfig,
    WebCapacityService, WebRestoredPositionImportEvidence,
};
use serde::Serialize;
use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const ADMIN_REQUEST_LIMIT: usize = 64 * 1024;
const IMPORT_INDEX_LIMIT: usize = 2 * 1024 * 1024;
const USAGE: &str = "usage:\n  noos-web-capacityd --config <path>\n  noos-web-capacityd queue-restore --config <path> --request <path> --report <new-path>\n  noos-web-capacityd export-restored-position --config <path> --position <0..11> --expires-at <unix-seconds> --output <new-path>\n  noos-web-capacityd release-restored-position --config <path> --index <path> --import-evidence <path> --report <new-path>";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Serve {
        config: PathBuf,
    },
    QueueRestore {
        config: PathBuf,
        request: PathBuf,
        report: PathBuf,
    },
    ExportRestoredPosition {
        config: PathBuf,
        position: u8,
        expires_at: u64,
        output: PathBuf,
    },
    ReleaseRestoredPosition {
        config: PathBuf,
        index: PathBuf,
        import_evidence: PathBuf,
        report: PathBuf,
    },
}
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("noos-web-capacityd: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    match parse_arguments(env::args_os().skip(1))? {
        Command::Serve { config } => serve(config).await,
        Command::QueueRestore {
            config,
            request,
            report,
        } => queue_restore(&config, &request, &report),
        Command::ExportRestoredPosition {
            config,
            position,
            expires_at,
            output,
        } => export_restored_position(&config, position, expires_at, &output),
        Command::ReleaseRestoredPosition {
            config,
            index,
            import_evidence,
            report,
        } => release_restored_position(&config, &index, &import_evidence, &report),
    }
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> std::result::Result<Command, String> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[0] == "--config" {
        return Ok(Command::Serve {
            config: PathBuf::from(&arguments[1]),
        });
    }
    if arguments.len() == 7
        && arguments[0] == "queue-restore"
        && arguments[1] == "--config"
        && arguments[3] == "--request"
        && arguments[5] == "--report"
    {
        return Ok(Command::QueueRestore {
            config: PathBuf::from(&arguments[2]),
            request: PathBuf::from(&arguments[4]),
            report: PathBuf::from(&arguments[6]),
        });
    }
    if arguments.len() == 9
        && arguments[0] == "export-restored-position"
        && arguments[1] == "--config"
        && arguments[3] == "--position"
        && arguments[5] == "--expires-at"
        && arguments[7] == "--output"
    {
        let position = arguments[4]
            .to_str()
            .ok_or_else(|| "--position must be UTF-8".to_owned())?
            .parse::<u8>()
            .map_err(|error| format!("invalid --position: {error}"))?;
        let expires_at = arguments[6]
            .to_str()
            .ok_or_else(|| "--expires-at must be UTF-8".to_owned())?
            .parse::<u64>()
            .map_err(|error| format!("invalid --expires-at: {error}"))?;
        return Ok(Command::ExportRestoredPosition {
            config: PathBuf::from(&arguments[2]),
            position,
            expires_at,
            output: PathBuf::from(&arguments[8]),
        });
    }
    if arguments.len() == 9
        && arguments[0] == "release-restored-position"
        && arguments[1] == "--config"
        && arguments[3] == "--index"
        && arguments[5] == "--import-evidence"
        && arguments[7] == "--report"
    {
        return Ok(Command::ReleaseRestoredPosition {
            config: PathBuf::from(&arguments[2]),
            index: PathBuf::from(&arguments[4]),
            import_evidence: PathBuf::from(&arguments[6]),
            report: PathBuf::from(&arguments[8]),
        });
    }
    Err(USAGE.to_owned())
}

async fn serve(config_path: PathBuf) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = WebCapacityConfig::load(&config_path)?;
    let listen = config.listen;
    let service = WebCapacityService::new(config)?;
    println!(
        "WWM experimental web capacity coordinator listening on http://{listen}; production custody=false rewards=false"
    );
    println!("No validator key, consensus store, model execution, or custody-certificate authority is loaded.");
    service.run().await?;
    Ok(())
}

fn queue_restore(
    config_path: &Path,
    request_path: &Path,
    report_path: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let request_bytes = fs::read(request_path)?;
    if request_bytes.len() > ADMIN_REQUEST_LIMIT {
        return Err(format!(
            "queue-restore request exceeds {ADMIN_REQUEST_LIMIT} bytes"
        )
        .into());
    }
    let request: QueueRestoreAdminRequest = serde_json::from_slice(&request_bytes)?;
    let config = WebCapacityConfig::load(config_path)?;
    let service = WebCapacityService::new(config)?;
    let mut report_file = reserve_report(report_path)?;
    let report = match service.queue_restore_admin(request) {
        Ok(report) => report,
        Err(error) => {
            drop(report_file);
            let _ = fs::remove_file(report_path);
            return Err(error.into());
        }
    };
    write_reserved_report(&mut report_file, &report)?;
    println!(
        "queued one signed experimental restore task; insert-once report written to {}",
        report_path.display()
    );
    Ok(())
}

fn export_restored_position(
    config_path: &Path,
    position: u8,
    expires_at: u64,
    output_path: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let generated_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if expires_at <= generated_at {
        return Err("--expires-at must be in the future".into());
    }
    let config = WebCapacityConfig::load(config_path)?;
    let service = WebCapacityService::new(config)?;
    let mut output_file = reserve_report(output_path)?;
    let index = match service.export_restored_position_index(
        position,
        generated_at,
        expires_at,
    ) {
        Ok(index) => index,
        Err(error) => {
            drop(output_file);
            let _ = fs::remove_file(output_path);
            return Err(error.into());
        }
    };
    write_reserved_report(&mut output_file, &index)?;
    println!(
        "wrote signed non-promoting restored-position import index to {}",
        output_path.display()
    );
    Ok(())
}

fn release_restored_position(
    config_path: &Path,
    index_path: &Path,
    import_evidence_path: &Path,
    report_path: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let index_bytes = read_bounded_regular(index_path, IMPORT_INDEX_LIMIT)?;
    let evidence_bytes = read_bounded_regular(import_evidence_path, ADMIN_REQUEST_LIMIT)?;
    let index: SignedRestoredPositionImportIndex = serde_json::from_slice(&index_bytes)?;
    let evidence: WebRestoredPositionImportEvidence = serde_json::from_slice(&evidence_bytes)?;
    let config = WebCapacityConfig::load(config_path)?;
    let service = WebCapacityService::new(config)?;
    let mut report_file = reserve_report(report_path)?;
    let released_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = match service.release_restored_position(&index, &evidence, released_at) {
        Ok(report) => report,
        Err(error) => {
            drop(report_file);
            let _ = fs::remove_file(report_path);
            return Err(error.into());
        }
    };
    write_reserved_report(&mut report_file, &report)?;
    println!(
        "released imported restored-position quarantine; insert-once report written to {}",
        report_path.display()
    );
    Ok(())
}

fn read_bounded_regular(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > maximum as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} must be a regular non-symlink file no larger than {maximum} bytes",
                path.display()
            ),
        ));
    }
    fs::read(path)
}

fn reserve_report(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create_new(true).write(true).open(path)
}

fn write_reserved_report<T: Serialize>(file: &mut File, report: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(report).map_err(std::io::Error::other)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;


    #[test]
    fn command_parser_is_closed_and_preserves_serve_compatibility() {
        assert_eq!(
            parse_arguments(["--config", "capacity.json"].map(OsString::from)).unwrap(),
            Command::Serve {
                config: PathBuf::from("capacity.json")
            }
        );
        assert_eq!(
            parse_arguments(
                [
                    "queue-restore",
                    "--config",
                    "capacity.json",
                    "--request",
                    "request.json",
                    "--report",
                    "report.json",
                ]
                .map(OsString::from)
            )
            .unwrap(),
            Command::QueueRestore {
                config: PathBuf::from("capacity.json"),
                request: PathBuf::from("request.json"),
                report: PathBuf::from("report.json"),
            }
        );
        assert_eq!(
            parse_arguments(
                [
                    "export-restored-position",
                    "--config",
                    "capacity.json",
                    "--position",
                    "3",
                    "--expires-at",
                    "1800000060",
                    "--output",
                    "index.json",
                ]
                .map(OsString::from)
            )
            .unwrap(),
            Command::ExportRestoredPosition {
                config: PathBuf::from("capacity.json"),
                position: 3,
                expires_at: 1_800_000_060,
                output: PathBuf::from("index.json"),
            }
        );
        assert_eq!(
            parse_arguments(
                [
                    "release-restored-position",
                    "--config",
                    "capacity.json",
                    "--index",
                    "index.json",
                    "--import-evidence",
                    "import-evidence.json",
                    "--report",
                    "release-report.json",
                ]
                .map(OsString::from)
            )
            .unwrap(),
            Command::ReleaseRestoredPosition {
                config: PathBuf::from("capacity.json"),
                index: PathBuf::from("index.json"),
                import_evidence: PathBuf::from("import-evidence.json"),
                report: PathBuf::from("release-report.json"),
            }
        );
        for rejected in [
            vec!["queue-restore", "--config", "capacity.json"],
            vec![
                "queue-restore",
                "--config",
                "capacity.json",
                "--request",
                "request.json",
                "--report",
                "report.json",
                "--listen",
                "0.0.0.0:9999",
            ],
            vec!["serve", "--config", "capacity.json"],
        ] {
            assert!(parse_arguments(rejected.into_iter().map(OsString::from)).is_err());
        }
    }

    #[test]
    fn report_reservation_is_insert_once() {
        let directory = tempdir().unwrap();
        let report_path = directory.path().join("report.json");
        let mut file = reserve_report(&report_path).unwrap();
        write_reserved_report(&mut file, &serde_json::json!({"insert_once": true})).unwrap();
        drop(file);
        assert!(reserve_report(&report_path).is_err());
        assert_eq!(
            fs::read_to_string(report_path).unwrap(),
            "{\n  \"insert_once\": true\n}\n"
        );
    }
    #[test]
    fn queue_restore_rejects_unbounded_or_nonclosed_json_before_side_effects() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("unused-config.json");
        let request_path = directory.path().join("request.json");
        let report_path = directory.path().join("report.json");

        fs::write(&request_path, vec![b' '; ADMIN_REQUEST_LIMIT + 1]).unwrap();
        let error = queue_restore(&config_path, &request_path, &report_path)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exceeds"));
        assert!(!report_path.exists());

        fs::write(&request_path, br#"{"unexpected":true}"#).unwrap();
        assert!(queue_restore(&config_path, &request_path, &report_path).is_err());
        assert!(!report_path.exists());
    }
}
