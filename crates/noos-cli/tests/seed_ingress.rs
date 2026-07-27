use std::io::Write as _;
use std::process::{Command, Stdio};

const SEED: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

#[test]
fn seed_enters_through_stdin_and_never_appears_in_output() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_noos-cli"))
        .args([
            "keygen",
            "--seed-stdin",
            "--purpose",
            "sign",
            "--account",
            "0",
            "--index",
            "0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn noos-cli");
    child
        .stdin
        .take()
        .expect("seed stdin")
        .write_all(format!("{SEED}\n").as_bytes())
        .expect("write seed");
    let output = child.wait_with_output().expect("wait for noos-cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(!stdout.contains(SEED), "seed leaked to stdout");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON output");
    assert_eq!(value["verifying_key"].as_str().map(str::len), Some(64));
}

#[test]
fn raw_seed_command_line_is_rejected_without_echoing_it() {
    let output = Command::new(env!("CARGO_BIN_EXE_noos-cli"))
        .args([
            "keygen",
            "--seed",
            SEED,
            "--purpose",
            "sign",
            "--account",
            "0",
            "--index",
            "0",
        ])
        .output()
        .expect("run noos-cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(stderr.contains("raw seed command-line arguments are forbidden"));
    assert!(!stderr.contains(SEED), "seed leaked to stderr");
}
