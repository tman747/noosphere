//! Spawns the real noos-workerd binary: exact receipt bytes, telemetry
//! lines, malformed handling, queue-mode backlog, graceful shutdown, and
//! the CLI contract. Expected bytes are recomputed here independently with
//! noos-crypto — the test never trusts the daemon's own encoders.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_crypto::{verify_domain, DomainId, Keypair, Signature};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SEED: [u8; 32] = [0x11; 32];
const CHAIN: [u8; 32] = [0x22; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("noos-workerd-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("workerd.toml");
    std::fs::write(
        &path,
        format!(
            "[worker]\nseed_hex = \"{}\"\nchain_id_hex = \"{}\"\n",
            hex(&SEED),
            hex(&CHAIN)
        ),
    )
    .unwrap();
    path
}

fn spawn_with_stdin(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_noos-workerd"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn noos-workerd");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    child.wait_with_output().expect("wait noos-workerd")
}

fn stdout_text(out: &Output) -> String {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .replace("\r\n", "\n")
}

#[test]
fn spawned_worker_emits_exact_receipt_bytes_and_telemetry() {
    let dir = temp_dir("receipt");
    let cfg = write_config(&dir);
    let job_id = [0xab_u8; 32];
    let input = format!("JOB {} relay replica 1 40 0\nSHUTDOWN\n", hex(&job_id));
    let out = spawn_with_stdin(&["legacy", "--config", cfg.to_str().unwrap()], &input);
    assert!(out.status.success(), "worker must exit 0 on SHUTDOWN");

    // Independent recomputation: replica + not directly reachable must take
    // the hearth relay fallback (class=1 relay, outcome=0, result=4, seq=1).
    let mut body = Vec::new();
    body.extend_from_slice(&CHAIN);
    body.extend_from_slice(&job_id);
    body.extend_from_slice(&[1, 0, 4]);
    body.extend_from_slice(&1_u64.to_le_bytes());
    let keypair = Keypair::from_seed(SEED);
    let sig = keypair
        .sign_domain(DomainId::SigWorkReceipt, &[&body])
        .unwrap();

    let expected = format!(
        "READY pubkey={}\n\
         RECEIPT body={} sig={}\n\
         METRIC noos_nel_finality_state_jobs{{state=\"terminal\"}} 1\n\
         METRIC noos_nel_finality_state_jobs{{state=\"terminal\"}} 1\n\
         METRIC noos_telemetry_contract_violations_total{{reason=\"malformed\"}} 0\n\
         SHUTDOWN jobs=1 violations=0\n",
        hex(keypair.public_key().as_bytes()),
        hex(&body),
        hex(&sig.into_bytes()),
    );
    assert_eq!(stdout_text(&out), expected, "exact output byte contract");
}

#[test]
fn emitted_receipt_verifies_and_forgeries_are_rejected() {
    let dir = temp_dir("forgery");
    let cfg = write_config(&dir);
    let job_id = [0x0f_u8; 32];
    let input = format!(
        "JOB {} audit 3000 chorus_advisory 0\nSHUTDOWN\n",
        hex(&job_id)
    );
    let out = spawn_with_stdin(&["legacy", "--config", cfg.to_str().unwrap()], &input);
    assert!(out.status.success());
    let text = stdout_text(&out);
    let receipt = text
        .lines()
        .find(|l| l.starts_with("RECEIPT "))
        .expect("a receipt line");
    let body_hex = receipt
        .split_ascii_whitespace()
        .find_map(|t| t.strip_prefix("body="))
        .unwrap();
    let sig_hex = receipt
        .split_ascii_whitespace()
        .find_map(|t| t.strip_prefix("sig="))
        .unwrap();
    let body = unhex(body_hex);
    assert_eq!(body.len(), 75);
    // Audit accepted by hearth admission and the wired Freivalds check.
    assert_eq!(&body[64..67], &[3, 0, 1]);
    let sig_bytes: [u8; 64] = unhex(sig_hex).as_slice().try_into().unwrap();
    let sig = Signature::from_bytes(sig_bytes);
    let public = Keypair::from_seed(SEED).public_key();
    verify_domain(DomainId::SigWorkReceipt, &public, &[&body], &sig)
        .expect("genuine receipt verifies");

    // Falsifier 1: any flipped body byte must fail verification.
    let mut forged = body.clone();
    forged[66] ^= 1;
    assert!(
        verify_domain(DomainId::SigWorkReceipt, &public, &[&forged], &sig).is_err(),
        "forged outcome byte must not verify"
    );
    // Falsifier 2: the receipt must be domain-bound, not a generic signature.
    assert!(
        verify_domain(DomainId::SigTx, &public, &[&body], &sig).is_err(),
        "receipt signature must not verify under a sibling domain"
    );
    // Falsifier 3: a different worker key cannot claim the receipt.
    let stranger = Keypair::from_seed([0x77; 32]).public_key();
    assert!(
        verify_domain(DomainId::SigWorkReceipt, &stranger, &[&body], &sig).is_err(),
        "a stranger key must not verify the receipt"
    );
}

#[test]
fn malformed_lines_count_violations_and_never_kill_the_daemon() {
    let dir = temp_dir("malformed");
    let cfg = write_config(&dir);
    let out = spawn_with_stdin(
        &["legacy", "--config", cfg.to_str().unwrap()],
        "BOGUS junk\nSHUTDOWN\n",
    );
    assert!(out.status.success(), "malformed input must not crash");
    let text = stdout_text(&out);
    assert!(text.contains("ERR malformed unknown_command"));
    assert!(
        text.contains("METRIC noos_telemetry_contract_violations_total{reason=\"malformed\"} 1")
    );
    assert!(text.ends_with("SHUTDOWN jobs=0 violations=1\n"));
    assert!(!text.contains("RECEIPT "), "no receipt for malformed input");
}

#[test]
fn queue_file_mode_reports_a_real_decreasing_backlog() {
    let dir = temp_dir("queue");
    let cfg = write_config(&dir);
    let queue = dir.join("queue.txt");
    std::fs::write(
        &queue,
        format!(
            "JOB {} seed replica 3 200 0\nJOB {} audit 3000 chorus_advisory 0\nSHUTDOWN\n",
            hex(&[0x01; 32]),
            hex(&[0x02; 32])
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_noos-workerd"))
        .args([
            "legacy",
            "--config",
            cfg.to_str().unwrap(),
            "--queue",
            queue.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout_text(&out);
    let backlog: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("noos_nel_verifier_backlog"))
        .collect();
    assert_eq!(
        backlog,
        vec![
            "METRIC noos_nel_verifier_backlog{profile=\"freivalds_v1\"} 1",
            "METRIC noos_nel_verifier_backlog{profile=\"freivalds_v1\"} 0",
            "METRIC noos_nel_verifier_backlog{profile=\"freivalds_v1\"} 0",
        ],
        "backlog counts remaining JOB lines, then drains to zero"
    );
    assert!(text.ends_with("SHUTDOWN jobs=2 violations=0\n"));
}

#[test]
fn eof_is_a_graceful_shutdown() {
    let dir = temp_dir("eof");
    let cfg = write_config(&dir);
    let out = spawn_with_stdin(&["legacy", "--config", cfg.to_str().unwrap()], "");
    assert!(out.status.success(), "EOF must terminate with exit 0");
    assert!(stdout_text(&out).ends_with("SHUTDOWN jobs=0 violations=0\n"));
}

#[test]
fn help_documents_the_protocol_and_exits_zero() {
    let out = Command::new(env!("CARGO_BIN_EXE_noos-workerd"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success(), "--help must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "noos-workerd",
        "legacy",
        "serve",
        "inspect",
        "prefetch",
        "drain",
        "--queue",
        "--config",
        "explicit",
    ] {
        assert!(text.contains(needle), "--help must document `{needle}`");
    }
}

#[test]
fn version_exits_zero_and_unknown_flag_is_a_usage_failure() {
    let version = Command::new(env!("CARGO_BIN_EXE_noos-workerd"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(!version.stdout.is_empty());

    let unknown = Command::new(env!("CARGO_BIN_EXE_noos-workerd"))
        .arg("--definitely-not-a-flag")
        .output()
        .unwrap();
    assert!(!unknown.status.success(), "unknown flags must not boot");

    let missing_cfg = Command::new(env!("CARGO_BIN_EXE_noos-workerd"))
        .args(["legacy", "--config", "does/not/exist.toml"])
        .output()
        .unwrap();
    assert!(!missing_cfg.status.success(), "missing config must fail");
}
