use noos_mind_gateway::service::web_capacity::{
    benchmark::{run_benchmark, ChurnDistribution},
    WebCapacityConfig,
};
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

const USAGE: &str = "usage: noos-web-capacity-bench --events <count> --seed <u64> --distribution <json> --config <json> --state-root <empty-directory> --report <new-json-path>";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("noos-web-capacity-bench: {error}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments(env::args().skip(1))?;
    if arguments.report.exists() {
        return Err(format!(
            "report path already exists; reports are create-new: {}",
            arguments.report.display()
        )
        .into());
    }
    let config = WebCapacityConfig::load(&arguments.config)?;
    let distribution = ChurnDistribution::from_path(&arguments.distribution)?;
    let report = run_benchmark(
        config,
        &arguments.state_root,
        &distribution,
        arguments.events,
        arguments.seed,
    )?;
    write_create_new(&arguments.report, &report)?;
    println!("{}", arguments.report.display());
    Ok(())
}

#[derive(Debug)]
struct Arguments {
    events: u64,
    seed: u64,
    distribution: PathBuf,
    config: PathBuf,
    state_root: PathBuf,
    report: PathBuf,
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Arguments, String> {
    let values = arguments.into_iter().collect::<Vec<_>>();
    if values.len() != 12 {
        return Err(USAGE.to_owned());
    }
    let mut events = None;
    let mut seed = None;
    let mut distribution = None;
    let mut config = None;
    let mut state_root = None;
    let mut report = None;
    for pair in values.chunks_exact(2) {
        match pair[0].as_str() {
            "--events" if events.is_none() => {
                let value = pair[1]
                    .parse::<u64>()
                    .map_err(|_| "--events must be a positive u64".to_owned())?;
                if value == 0 {
                    return Err("--events must be a positive u64".to_owned());
                }
                events = Some(value);
            }
            "--seed" if seed.is_none() => {
                seed = Some(
                    pair[1]
                        .parse::<u64>()
                        .map_err(|_| "--seed must be a u64".to_owned())?,
                );
            }
            "--distribution" if distribution.is_none() => {
                distribution = Some(PathBuf::from(&pair[1]));
            }
            "--config" if config.is_none() => config = Some(PathBuf::from(&pair[1])),
            "--state-root" if state_root.is_none() => state_root = Some(PathBuf::from(&pair[1])),
            "--report" if report.is_none() => report = Some(PathBuf::from(&pair[1])),
            flag => return Err(format!("unknown or duplicate argument: {flag}")),
        }
    }
    Ok(Arguments {
        events: events.ok_or_else(|| "missing --events".to_owned())?,
        seed: seed.ok_or_else(|| "missing --seed".to_owned())?,
        distribution: distribution.ok_or_else(|| "missing --distribution".to_owned())?,
        config: config.ok_or_else(|| "missing --config".to_owned())?,
        state_root: state_root.ok_or_else(|| "missing --state-root".to_owned())?,
        report: report.ok_or_else(|| "missing --report".to_owned())?,
    })
}

fn write_create_new<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
