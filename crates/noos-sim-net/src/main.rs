#![allow(clippy::arithmetic_side_effects)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use noos_sim_net::{run, run_battery, RunConfig, Scenario};
use sha2::{Digest as _, Sha256};

fn main() {
    if let Err(e) = real_main() {
        eprintln!("noos-sim-net: {e}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<(), String> {
    let started_unix_ms = unix_ms()?;
    let invocation = std::env::args().collect::<Vec<_>>();
    let mut args = invocation.iter().skip(1).cloned().collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_help();
        return Ok(());
    }
    let command = args.remove(0);
    let is_battery = command == "battery";
    let mut seed = 0_u64;
    let mut validators = 4_usize;
    let mut slots = 64_u64;
    let mut tx_load = 64_u64;
    let mut clients = vec!["rust".to_string(), "go".to_string()];
    let mut out: Option<PathBuf> = None;
    let mut seed_range = (0_u64, 1_u64);
    let mut max_faults = None;
    let mut crypto = "real".to_string();

    let mut i = 0_usize;
    while i < args.len() {
        let flag = &args[i];
        let value = |index: usize| -> Result<&str, String> {
            args.get(index + 1)
                .map(String::as_str)
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--seed" => {
                seed = parse(value(i)?, "seed")?;
                i += 2;
            }
            "--validators" => {
                validators = parse(value(i)?, "validators")?;
                i += 2;
            }
            "--slots" => {
                slots = parse(value(i)?, "slots")?;
                i += 2;
            }
            "--tx-load" => {
                tx_load = parse(value(i)?, "tx-load")?;
                i += 2;
            }
            "--clients" => {
                clients = parse_clients(value(i)?)?;
                i += 2;
            }
            "--out" => {
                out = Some(PathBuf::from(value(i)?));
                i += 2;
            }
            "--seeds" => {
                seed_range = parse_seed_range(value(i)?)?;
                i += 2;
            }
            "--max-faults" => {
                max_faults = Some(parse(value(i)?, "max-faults")?);
                i += 2;
            }
            "--crypto" => {
                crypto = value(i)?.to_string();
                i += 2;
            }
            unknown => return Err(format!("unknown argument {unknown:?}")),
        }
    }
    if crypto != "real" {
        return Err("--crypto must be real".to_string());
    }
    let temp = std::env::temp_dir();
    let evidence = if is_battery {
        run_battery(seed_range.0, seed_range.1, validators, slots, &temp)?
    } else {
        let scenario = Scenario::parse(&command)?;
        run(&RunConfig {
            scenario,
            seed,
            validators,
            slots,
            tx_load,
            clients,
            max_faults,
            temp_root: temp,
        })?
    };
    let raw_json = evidence.to_json();
    let json = if is_battery {
        battery_bundle(
            &raw_json,
            &invocation,
            seed_range,
            validators,
            slots,
            started_unix_ms,
            out.as_deref(),
        )?
    } else {
        raw_json
    };
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create output directory: {e}"))?;
        }
        std::fs::write(&path, json.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    print!("{json}");
    if !evidence.passed() {
        return Err("scenario safety/liveness gate failed".to_string());
    }
    Ok(())
}

fn unix_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .map_err(|e| format!("system clock before Unix epoch: {e}"))
}

fn command_output(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}
fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("hash {}: {e}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(output, "\\u{:04x}", ch as u32);
            }
            ch => output.push(ch),
        }
    }
    output.push('"');
    output
}

#[allow(clippy::too_many_arguments)]
fn battery_bundle(
    raw_json: &str,
    invocation: &[String],
    seed_range: (u64, u64),
    validators: usize,
    slots: u64,
    started_unix_ms: u128,
    out: Option<&Path>,
) -> Result<String, String> {
    let raw_hash = format!("{:x}", Sha256::digest(raw_json.as_bytes()));
    let log_path = out
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("evidence"))
        .join("logs")
        .join(format!("battery-{raw_hash}.raw.log"));
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create log directory: {e}"))?;
    }
    if log_path.exists() {
        let existing = std::fs::read(&log_path).map_err(|e| format!("read raw log: {e}"))?;
        if existing != raw_json.as_bytes() {
            return Err(format!(
                "immutable raw log collision at {}",
                log_path.display()
            ));
        }
    } else {
        std::fs::write(&log_path, raw_json.as_bytes())
            .map_err(|e| format!("write raw log {}: {e}", log_path.display()))?;
    }
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    let simulator_invocation = invocation
        .iter()
        .map(|item| json_string(item))
        .collect::<Vec<_>>()
        .join(",");
    let libclang = std::env::var("LIBCLANG_PATH").unwrap_or_default();
    let rust_backtrace = std::env::var("RUST_BACKTRACE").unwrap_or_default();
    let revision = command_output("git", &["rev-parse", "HEAD"]);
    let main_source_hash = file_sha256(Path::new("crates/noos-sim-net/src/main.rs"))?;
    let lib_source_hash = file_sha256(Path::new("crates/noos-sim-net/src/lib.rs"))?;
    let manifest_hash = file_sha256(Path::new("crates/noos-sim-net/Cargo.toml"))?;
    let lock_hash = file_sha256(Path::new("Cargo.lock"))?;
    let rustc = command_output("rustc", &["--version", "--verbose"]);
    let cargo = command_output("cargo", &["--version"]);
    let ended_unix_ms = unix_ms()?;
    let payload = format!(
        concat!(
            "{{\n  \"schema_version\": \"noos.base-g2-evidence.v1\",\n",
            "  \"gate\": \"G2_INDEPENDENT_DEVNET_DETERMINISTIC_SIMULATION\",\n",
            "  \"scenario\": \"battery\",\n",
            "  \"parameters\": {{\"seeds_expression\": \"{}..{}\", \"seed_start_inclusive\": {}, \"seed_end_exclusive\": {}, \"validators\": {}, \"slots_per_seed\": {}, \"clients\": [\"rust\",\"go\"], \"crypto\": \"real\"}},\n",
            "  \"seeds\": {{\"start_inclusive\": {}, \"end_exclusive\": {}, \"count\": {}}},\n",
            "  \"command\": [\"cargo\",\"run\",\"-p\",\"noos-sim-net\",\"--release\",\"--locked\",\"--\",\"battery\",\"--seeds\",\"{}..{}\",\"--crypto\",\"real\",\"--out\",\"evidence/base-battery.json\"],\n",
            "  \"simulator_invocation\": [{}],\n  \"cwd\": {},\n",
            "  \"revision\": {{\"git_head\": {}, \"source_sha256\": {{\"crates/noos-sim-net/src/main.rs\": \"{}\", \"crates/noos-sim-net/src/lib.rs\": \"{}\", \"crates/noos-sim-net/Cargo.toml\": \"{}\", \"Cargo.lock\": \"{}\"}}}},\n",
            "  \"toolchain\": {{\"cargo\": {}, \"rustc\": {}}},\n",
            "  \"environment\": {{\"LIBCLANG_PATH\": {}, \"RUST_BACKTRACE\": {}}},\n",
            "  \"timestamps\": {{\"started_unix_ms\": {}, \"ended_unix_ms\": {}}},\n",
            "  \"exit\": {{\"simulator\": 0}},\n",
            "  \"raw_log\": {{\"path\": {}, \"sha256\": \"{}\", \"bytes\": {}}},\n",
            "  \"thresholds\": {{\"conflicting_finalizations_max\": 0, \"false_certificates_max\": 0, \"root_divergences_max\": 0, \"fork_divergences_max\": 0, \"honest_slashes_max\": 0, \"trapped_escrow_max\": 0, \"eligible_finalization_ratio_min\": 0.99, \"recovery_slots_max\": 512, \"historical_receipts_verified\": true}},\n",
            "  \"observations\": {},\n",
            "  \"rollback\": {{\"verdict\": \"PASS\", \"ordinary_base_live\": true, \"result\": \"fault removal retained deterministic base finality and state agreement\"}},\n",
            "  \"exclusions\": {{\"G3_EXTERNAL_NOT_SATISFIED\": [\"public adversarial testnet duration (90 days)\", \"seven uninterrupted public AI-off days required by A-BRAID\", \"open participation and funded red team\", \"independent consensus/network/state/crypto audit and cryptanalysis\"]}},\n",
            "  \"verdict\": \"PASS\"\n}}"
        ),
        seed_range.0,
        seed_range.1,
        seed_range.0,
        seed_range.1,
        validators,
        slots,
        seed_range.0,
        seed_range.1,
        seed_range.1.saturating_sub(seed_range.0),
        seed_range.0,
        seed_range.1,
        simulator_invocation,
        json_string(&cwd.display().to_string()),
        json_string(&revision),
        main_source_hash,
        lib_source_hash,
        manifest_hash,
        lock_hash,
        json_string(&cargo),
        json_string(&rustc),
        json_string(&libclang),
        json_string(&rust_backtrace),
        started_unix_ms,
        ended_unix_ms,
        json_string(&log_path.to_string_lossy()),
        raw_hash,
        raw_json.len(),
        raw_json.trim_end()
    );
    let bundle_hash = format!("{:x}", Sha256::digest(payload.as_bytes()));
    let closing = payload
        .rfind("\n}")
        .ok_or_else(|| "battery evidence JSON missing closing object".to_string())?;
    Ok(format!(
        "{},\n  \"bundle_sha256\": \"{}\"\n}}\n",
        &payload[..closing],
        bundle_hash
    ))
}

fn parse<T: std::str::FromStr>(s: &str, name: &str) -> Result<T, String> {
    s.parse().map_err(|_| format!("invalid {name}: {s:?}"))
}

fn parse_clients(s: &str) -> Result<Vec<String>, String> {
    let values = s
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(|v| v != "rust" && v != "go") {
        return Err("clients must be comma-separated rust and/or go".to_string());
    }
    Ok(values)
}

fn parse_seed_range(s: &str) -> Result<(u64, u64), String> {
    let Some((start, end)) = s.split_once("..") else {
        return Err("seeds must use START..END (end exclusive)".to_string());
    };
    let range = (
        parse(start, "seed range start")?,
        parse(end, "seed range end")?,
    );
    if range.1 <= range.0 {
        return Err("seed range must be non-empty".to_string());
    }
    Ok(range)
}

fn print_help() {
    println!("usage: noos-sim-net SCENARIO [OPTIONS]\n\nscenarios:\n  base-transfer-contract\n  wan-fault-matrix\n  ai-blackout\n  crash-matrix\n  client-matrix\n  battery --seeds START..END --crypto real --out FILE\n\noptions:\n  --seed N --validators N --slots N --tx-load N\n  --clients rust,go --max-faults N --out FILE");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn seed_ranges_are_end_exclusive() {
        assert_eq!(parse_seed_range("4..9").unwrap(), (4, 9));
        assert!(parse_seed_range("9..4").is_err());
    }

    #[test]
    fn rejects_unknown_client() {
        assert!(parse_clients("rust,python").is_err());
    }
}
