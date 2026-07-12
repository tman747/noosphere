//! noosd CLI contract (node-v1.md §10.7): `--help` and `--version` work,
//! and an unknown flag is a typed usage failure, never a silent boot.

#![allow(clippy::expect_used)]
use std::process::Command;

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
