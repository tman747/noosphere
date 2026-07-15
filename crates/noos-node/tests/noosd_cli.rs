//! noosd CLI contract (node-v1.md §10.7): `--help` and `--version` work,
//! and an unknown flag is a typed usage failure, never a silent boot.

#![allow(clippy::expect_used)]
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn noosd(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_noosd"))
        .args(args)
        .output()
        .expect("run noosd")
}

#[test]
fn help_prints_the_operator_surface_and_exits_zero() {
    let out = noosd(&["--help"]);
    assert!(out.status.success(), "--help must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("noosd"), "names the binary");
    assert!(text.contains("--observer"), "documents observer mode");
    assert!(
        text.contains("--social-checkpoint"),
        "documents the SOCIAL input"
    );
    assert!(text.contains("--rpc"), "documents the operator RPC");
    assert!(
        text.contains("--devnet-witness-fixture"),
        "documents verification-only devnet witness bonds"
    );
    assert!(
        text.contains("--rpc-token-file"),
        "documents the command-line-secret-safe RPC token file"
    );
    assert!(
        text.contains("NEVER") || text.contains("never"),
        "the social-checkpoint law is stated"
    );
}

#[test]
fn version_exits_zero() {
    let out = noosd(&["--version"]);
    assert!(out.status.success(), "--version must exit 0");
    assert!(!out.stdout.is_empty());
}

#[test]
fn unknown_flag_is_a_usage_failure() {
    let out = noosd(&["--definitely-not-a-flag"]);
    assert!(!out.status.success(), "unknown flags must not boot a node");
}

#[test]
fn rpc_token_file_failures_are_typed_before_node_boot() {
    let missing = std::env::temp_dir().join(format!(
        "noosd-missing-token-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    let out = noosd(&["--rpc-token-file", missing.to_str().expect("UTF-8 temp path")]);
    assert!(!out.status.success(), "missing token file must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("read --rpc-token-file"),
        "missing token file has a typed diagnostic"
    );

    let short = missing.with_extension("short");
    fs::write(&short, "too-short\n").expect("write short token");
    let out = noosd(&["--rpc-token-file", short.to_str().expect("UTF-8 temp path")]);
    fs::remove_file(&short).expect("remove short token");
    assert!(!out.status.success(), "short token file must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("at least 32 characters"),
        "short token file has a typed diagnostic"
    );

    let out = noosd(&[
        "--rpc-token",
        "this-token-is-long-enough-but-still-command-line",
        "--rpc-token-file",
        missing.to_str().expect("UTF-8 temp path"),
    ]);
    assert!(!out.status.success(), "two token sources must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("mutually exclusive"),
        "conflicting token sources have a typed diagnostic"
    );
}
