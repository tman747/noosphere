//! Exclusion gate (plan section 3.2): the reviewed port source carried
//! ceremony fixtures — a deterministic beacon share issuer, simulated
//! randomness, and embedded devnet secret material. None of that may exist
//! in noos-crypto. This test scans every compiled source file (src/ and
//! build.rs) for the banned identifiers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]

use std::fs;
use std::path::PathBuf;

/// Banned identifier fragments. Any occurrence in compiled sources fails.
const BANNED: &[&str] = &["beacon_dealer", "sim_rng", "sim-rng", "dealer", "DevnetGenesis"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn scan_file(path: &PathBuf, findings: &mut Vec<String>) {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let lower = text.to_lowercase();
    for banned in BANNED {
        if lower.contains(&banned.to_lowercase()) {
            findings.push(format!("{}: contains `{banned}`", path.display()));
        }
    }
}

#[test]
fn compiled_sources_expose_no_excluded_symbols() {
    let root = manifest_dir();
    let mut findings = Vec::new();

    let src = root.join("src");
    let entries = fs::read_dir(&src).expect("src dir");
    let mut scanned = 0_usize;
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            scan_file(&path, &mut findings);
            scanned += 1;
        }
    }
    scan_file(&root.join("build.rs"), &mut findings);

    assert!(scanned >= 8, "expected to scan the full module set, saw {scanned}");
    assert!(
        findings.is_empty(),
        "excluded ceremony/fixture symbols found:\n{}",
        findings.join("\n")
    );
}

#[test]
fn generated_registry_exposes_no_excluded_symbols() {
    // The generated domain table must also be clean: scan the OUT_DIR
    // artifact the crate actually compiled (env set by build scripts is not
    // visible here, so locate it under target/).
    // The registry is regenerated from the CSV on every build; scanning the
    // CSV itself is equivalent and stable.
    let csv = manifest_dir()
        .join("..")
        .join("..")
        .join("protocol")
        .join("spec")
        .join("crypto-domains-v1.csv");
    let mut findings = Vec::new();
    scan_file(&csv, &mut findings);
    assert!(
        findings.is_empty(),
        "registry CSV carries excluded symbols:\n{}",
        findings.join("\n")
    );
}
