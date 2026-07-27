use noos_mind::assurance::run_knowledge_assurance_campaign;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("knowledge assurance campaign failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut source_revision = None;
    let mut seed = 0_u64;
    let mut output = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--source-revision" => {
                source_revision = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--source-revision requires a value".to_owned())?,
                );
            }
            "--seed" => {
                seed = arguments
                    .next()
                    .ok_or_else(|| "--seed requires a value".to_owned())?
                    .parse::<u64>()
                    .map_err(|_| "--seed must be an unsigned integer".to_owned())?;
            }
            "--output" => {
                output = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--output requires a value".to_owned())?,
                ));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let source_revision = source_revision.ok_or_else(|| "missing --source-revision".to_owned())?;
    let output = output.ok_or_else(|| "missing --output".to_owned())?;
    let report = run_knowledge_assurance_campaign(&source_revision, seed)
        .map_err(|error| format!("{error:?}"))?;
    write_immutable_json(&output, &report)?;
    println!(
        "knowledge assurance campaign PASS: {} scenarios -> {}",
        report.steps.len(),
        output.display()
    );
    Ok(())
}

fn write_immutable_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if path.exists() {
        return Err(format!("refusing to overwrite {}", path.display()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "output path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "output filename is not UTF-8".to_owned())?,
        std::process::id()
    ));
    let result = (|| {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, value)
            .map_err(|error| format!("serialize report: {error}"))?;
        writer
            .write_all(b"\n")
            .map_err(|error| format!("write report: {error}"))?;
        writer
            .flush()
            .map_err(|error| format!("flush report: {error}"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync report: {error}"))?;
        fs::hard_link(&temporary, path)
            .map_err(|error| format!("publish {}: {error}", path.display()))?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}
