//! Deterministic job intake, dispatch, receipt signing, and shutdown.
//!
//! The run loop takes no wall clock and no OS randomness: identical input
//! plus identical config produce identical output bytes. All state that a
//! receipt binds is explicit in the receipt body.
pub mod llama_cpp;
pub mod process;

use crate::config::Config;
use crate::hex::{decode_hex32, encode_hex};
use crate::telemetry;
use noos_crypto::{DomainId, Keypair, PublicKey, Signature};
use noos_hearth::{
    admit_custody, route, CustodyRole, HearthError, JobShape, NetworkConditions, Route,
};
use noos_nel::{freivalds_verify_u64, FreivaldsProfile};
use std::io::{self, Write};

/// chain_id(32) || job_id(32) || class(1) || outcome(1) || result(1) || seq_le(8)
pub const RECEIPT_BODY_LEN: usize = 75;

/// Job classes accepted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobClass {
    /// Route a job shape through hearth WAN/relay routing (not seeding).
    Relay,
    /// Route with `is_seeding = true`: many-source seeding path.
    Seed,
    /// Custody admission through hearth, then a NEL Freivalds self-audit.
    Audit,
}

/// Class byte on the receipt wire.
#[must_use]
pub const fn class_code(class: JobClass) -> u8 {
    match class {
        JobClass::Relay => 1,
        JobClass::Seed => 2,
        JobClass::Audit => 3,
    }
}

/// Route byte on the receipt wire (outcome 0 for relay/seed jobs).
#[must_use]
pub const fn route_code(r: Route) -> u8 {
    match r {
        Route::LanInteractive => 1,
        Route::WanReplica => 2,
        Route::WanBatch => 3,
        Route::RelayFallback => 4,
        Route::ManySourceSeeding => 5,
    }
}

/// Stable hearth rejection byte on the receipt wire (outcome 1).
#[must_use]
pub const fn hearth_error_code(err: &HearthError) -> u8 {
    match err {
        HearthError::OneHouseholdOneStreamViolation => 1,
        HearthError::ImmutableManifest => 2,
        HearthError::InvalidSignedPlan => 3,
        HearthError::InvalidPartition => 4,
        HearthError::UnknownDevice => 5,
        HearthError::InvalidAvailability => 6,
        HearthError::AvailabilityClassIneligible => 7,
        HearthError::InvalidShard => 8,
        HearthError::DuplicateShard => 9,
        HearthError::CorruptShardRejected => 10,
        HearthError::FalseCorruptionReport => 11,
        HearthError::PromotionRequiresNewSpeciesRevision => 12,
        HearthError::DreamMarketKilled => 13,
        HearthError::CausalInsulationRequired => 14,
        HearthError::RevealDeadline => 15,
        HearthError::RealizationAlreadyUsed => 16,
        HearthError::ActionFirewall => 17,
        HearthError::InteractiveMustRemainLan => 18,
        HearthError::FeatureDisabled { .. } => 19,
    }
}

/// Per-class execution parameters parsed from a JOB line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobSpec {
    /// Relay/seed: hearth routing inputs.
    Net {
        shape: JobShape,
        hops: u8,
        rtt_ms: u32,
        direct: bool,
    },
    /// Audit: hearth custody admission inputs.
    Audit {
        availability_bps: u16,
        role: CustodyRole,
        gate: bool,
    },
}

/// A fully parsed JOB line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobLine {
    pub job_id: [u8; 32],
    pub class: JobClass,
    pub spec: JobSpec,
}

/// One intake command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Job(JobLine),
    Shutdown,
}

fn parse_shape(token: &str) -> Result<JobShape, &'static str> {
    match token {
        "interactive" => Ok(JobShape::Interactive),
        "replica" => Ok(JobShape::Replica),
        "wan_batch" => Ok(JobShape::WanBatch),
        "stateless" => Ok(JobShape::Stateless),
        "reissueable" => Ok(JobShape::Reissueable),
        "stateful_custody" => Ok(JobShape::StatefulCustody),
        "chorus_advisory" => Ok(JobShape::ChorusAdvisory),
        _ => Err("bad_shape"),
    }
}

fn parse_role(token: &str) -> Result<CustodyRole, &'static str> {
    match token {
        "stateful_production" => Ok(CustodyRole::StatefulProduction),
        "stateless_reissueable" => Ok(CustodyRole::StatelessReissueable),
        "chorus_advisory" => Ok(CustodyRole::ChorusAdvisory),
        _ => Err("bad_role"),
    }
}

fn parse_flag(token: &str, err: &'static str) -> Result<bool, &'static str> {
    match token {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(err),
    }
}

fn parse_net_args<'a>(it: &mut impl Iterator<Item = &'a str>) -> Result<JobSpec, &'static str> {
    let shape = parse_shape(it.next().ok_or("missing_shape")?)?;
    let hops: u8 = it
        .next()
        .ok_or("missing_hops")?
        .parse()
        .map_err(|_| "bad_hops")?;
    let rtt_ms: u32 = it
        .next()
        .ok_or("missing_rtt")?
        .parse()
        .map_err(|_| "bad_rtt")?;
    let direct = parse_flag(it.next().ok_or("missing_direct")?, "bad_direct")?;
    Ok(JobSpec::Net {
        shape,
        hops,
        rtt_ms,
        direct,
    })
}

fn parse_audit_args<'a>(it: &mut impl Iterator<Item = &'a str>) -> Result<JobSpec, &'static str> {
    let availability_bps: u16 = it
        .next()
        .ok_or("missing_availability")?
        .parse()
        .map_err(|_| "bad_availability")?;
    let role = parse_role(it.next().ok_or("missing_role")?)?;
    let gate = parse_flag(it.next().ok_or("missing_gate")?, "bad_gate")?;
    Ok(JobSpec::Audit {
        availability_bps,
        role,
        gate,
    })
}

/// Parses one intake line. `Ok(None)` is a blank line (ignored).
pub fn parse_line(line: &str) -> Result<Option<Command>, &'static str> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let mut it = trimmed.split_ascii_whitespace();
    let head = it.next().ok_or("unknown_command")?;
    let command = match head {
        "SHUTDOWN" => Command::Shutdown,
        "JOB" => {
            let job_id = decode_hex32(it.next().ok_or("missing_job_id")?).ok_or("bad_job_id")?;
            let class = match it.next().ok_or("missing_class")? {
                "relay" => JobClass::Relay,
                "seed" => JobClass::Seed,
                "audit" => JobClass::Audit,
                _ => return Err("bad_class"),
            };
            let spec = match class {
                JobClass::Relay | JobClass::Seed => parse_net_args(&mut it)?,
                JobClass::Audit => parse_audit_args(&mut it)?,
            };
            Command::Job(JobLine {
                job_id,
                class,
                spec,
            })
        }
        _ => return Err("unknown_command"),
    };
    if it.next().is_some() {
        return Err("trailing_tokens");
    }
    Ok(Some(command))
}

/// Wired 2x2x2 Freivalds self-audit exercised by every audit job. The
/// matrices satisfy `A x B = C`, so a healthy verifier accepts; a broken or
/// substituted verifier is surfaced as outcome 2 on the signed receipt.
const AUDIT_A: [u64; 4] = [1, 2, 3, 4];
const AUDIT_B: [u64; 4] = [5, 6, 7, 8];
const AUDIT_C: [u64; 4] = [19, 22, 43, 50];

fn self_audit() -> (u8, u8) {
    let vectors = [vec![1_u32, 2], vec![3_u32, 5]];
    match freivalds_verify_u64(
        &AUDIT_A,
        &AUDIT_B,
        &AUDIT_C,
        2,
        2,
        2,
        &vectors,
        FreivaldsProfile::StandardReps2,
    ) {
        Ok(true) => (0, 1),
        Ok(false) => (2, 1),
        Err(_) => (2, 0),
    }
}

/// Runs the real hearth state machine (and, for audits, the NEL verifier)
/// for one job. Returns `(outcome, result)` receipt bytes:
/// outcome 0 = accepted (result = route code, or 1 for a clean audit),
/// outcome 1 = hearth rejection (result = [`hearth_error_code`]),
/// outcome 2 = verifier failure (audit only).
#[must_use]
pub fn execute(class: JobClass, spec: &JobSpec) -> (u8, u8) {
    match *spec {
        JobSpec::Net {
            shape,
            hops,
            rtt_ms,
            direct,
        } => {
            let net = NetworkConditions {
                hops,
                rtt_ms,
                direct_reachable: direct,
                is_seeding: class == JobClass::Seed,
            };
            match route(shape, net) {
                Ok(r) => (0, route_code(r)),
                Err(e) => (1, hearth_error_code(&e)),
            }
        }
        JobSpec::Audit {
            availability_bps,
            role,
            gate,
        } => match admit_custody(availability_bps, role, gate) {
            Ok(()) => self_audit(),
            Err(e) => (1, hearth_error_code(&e)),
        },
    }
}

/// Receipt-signing worker state.
pub struct Worker {
    keypair: Keypair,
    chain_id: [u8; 32],
    seq: u64,
    pub jobs_done: u64,
    pub violations: u64,
}

impl Worker {
    #[must_use]
    pub fn new(cfg: &Config) -> Self {
        Self {
            keypair: Keypair::from_seed(cfg.seed),
            chain_id: cfg.chain_id,
            seq: 0,
            jobs_done: 0,
            violations: 0,
        }
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Builds the next receipt body; sequence numbers start at 1.
    pub fn next_receipt_body(
        &mut self,
        job_id: &[u8; 32],
        class: u8,
        outcome: u8,
        result: u8,
    ) -> [u8; RECEIPT_BODY_LEN] {
        self.seq = self.seq.saturating_add(1);
        let mut body = [0_u8; RECEIPT_BODY_LEN];
        body[..32].copy_from_slice(&self.chain_id);
        body[32..64].copy_from_slice(job_id);
        body[64] = class;
        body[65] = outcome;
        body[66] = result;
        body[67..75].copy_from_slice(&self.seq.to_le_bytes());
        body
    }

    /// Signs a receipt body under the registered `D-SIG-WORK-RECEIPT`
    /// domain (`NOOS/SIG/WORK_RECEIPT/V1`), never a raw message.
    pub fn sign(&self, body: &[u8; RECEIPT_BODY_LEN]) -> io::Result<Signature> {
        self.keypair
            .sign_domain(DomainId::SigWorkReceipt, &[body])
            .map_err(|_| io::Error::other("receipt signing failed"))
    }
}

fn is_job_line(line: &str) -> bool {
    line.trim().split_ascii_whitespace().next() == Some("JOB")
}

/// Counts JOB-headed lines: the initial verifier backlog in queue mode.
#[must_use]
pub fn count_job_lines(lines: &[String]) -> usize {
    lines.iter().filter(|l| is_job_line(l)).count()
}

fn backlog_value(pending: usize) -> u64 {
    u64::try_from(pending).unwrap_or(u64::MAX)
}

/// The deterministic intake loop. `pending_jobs` is `Some` only in queue
/// mode, where the remaining JOB-line count is known and reported as
/// verifier backlog. EOF and `SHUTDOWN` both terminate gracefully.
pub fn run<I, W>(cfg: &Config, lines: I, pending_jobs: Option<usize>, out: &mut W) -> io::Result<()>
where
    I: IntoIterator<Item = io::Result<String>>,
    W: Write,
{
    let mut worker = Worker::new(cfg);
    let mut pending = pending_jobs;
    writeln!(
        out,
        "READY pubkey={}",
        encode_hex(worker.public_key().as_bytes())
    )?;
    for line in lines {
        let line = line?;
        let job_headed = is_job_line(&line);
        if job_headed {
            if let Some(p) = pending.as_mut() {
                *p = p.saturating_sub(1);
            }
        }
        match parse_line(&line) {
            Ok(None) => {}
            Ok(Some(Command::Shutdown)) => break,
            Ok(Some(Command::Job(job))) => {
                let (outcome, result) = execute(job.class, &job.spec);
                let body =
                    worker.next_receipt_body(&job.job_id, class_code(job.class), outcome, result);
                let sig = worker.sign(&body)?;
                writeln!(
                    out,
                    "RECEIPT body={} sig={}",
                    encode_hex(&body),
                    encode_hex(&sig.into_bytes())
                )?;
                worker.jobs_done = worker.jobs_done.saturating_add(1);
                writeln!(out, "{}", telemetry::terminal_jobs_line(worker.jobs_done))?;
                if let Some(p) = pending {
                    writeln!(out, "{}", telemetry::backlog_line(backlog_value(p)))?;
                }
            }
            Err(reason) => {
                worker.violations = worker.violations.saturating_add(1);
                writeln!(out, "ERR malformed {reason}")?;
                writeln!(out, "{}", telemetry::violations_line(worker.violations))?;
                if job_headed {
                    if let Some(p) = pending {
                        writeln!(out, "{}", telemetry::backlog_line(backlog_value(p)))?;
                    }
                }
            }
        }
    }
    writeln!(out, "{}", telemetry::terminal_jobs_line(worker.jobs_done))?;
    writeln!(out, "{}", telemetry::violations_line(worker.violations))?;
    if let Some(p) = pending {
        writeln!(out, "{}", telemetry::backlog_line(backlog_value(p)))?;
    }
    writeln!(
        out,
        "SHUTDOWN jobs={} violations={}",
        worker.jobs_done, worker.violations
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use noos_crypto::verify_domain;

    fn cfg() -> Config {
        Config {
            seed: [0x11; 32],
            chain_id: [0x22; 32],
        }
    }

    fn run_to_string(input: &str, pending: Option<usize>) -> String {
        let mut out = Vec::new();
        let lines = input.lines().map(|l| Ok(l.to_owned()));
        run(&cfg(), lines, pending, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn relay_replica_without_direct_reachability_falls_back_to_relay() {
        let job = parse_line(&format!("JOB {} relay replica 1 40 0", "ab".repeat(32)))
            .unwrap()
            .unwrap();
        let Command::Job(job) = job else {
            panic!("expected job")
        };
        assert_eq!(
            execute(job.class, &job.spec),
            (0, route_code(Route::RelayFallback))
        );
    }

    #[test]
    fn seed_class_forces_many_source_seeding_for_every_shape() {
        for shape in [
            "interactive",
            "replica",
            "wan_batch",
            "stateless",
            "reissueable",
            "stateful_custody",
            "chorus_advisory",
        ] {
            let line = format!("JOB {} seed {shape} 3 200 0", "cd".repeat(32));
            let Some(Command::Job(job)) = parse_line(&line).unwrap() else {
                panic!("expected job")
            };
            assert_eq!(
                execute(job.class, &job.spec),
                (0, route_code(Route::ManySourceSeeding)),
                "shape {shape}"
            );
        }
    }

    #[test]
    fn wan_interactive_is_a_typed_hearth_rejection_on_the_receipt() {
        let line = format!("JOB {} relay interactive 2 60 1", "ee".repeat(32));
        let Some(Command::Job(job)) = parse_line(&line).unwrap() else {
            panic!("expected job")
        };
        // Real hearth law: WAN per-token pipeline is disabled.
        assert_eq!(
            execute(job.class, &job.spec),
            (
                1,
                hearth_error_code(&HearthError::FeatureDisabled {
                    feature: "wan_per_token_pipeline",
                    evidence: "E-HEARTH-05",
                })
            )
        );
    }

    #[test]
    fn audit_admission_and_verifier_paths() {
        // Eligible casual availability: admitted, verifier accepts.
        let ok = format!("JOB {} audit 3000 stateless_reissueable 0", "aa".repeat(32));
        let Some(Command::Job(job)) = parse_line(&ok).unwrap() else {
            panic!("expected job")
        };
        assert_eq!(execute(job.class, &job.spec), (0, 1));
        // Below the stateful-production floor without the gate: rejected by
        // the real hearth admission law, not by this daemon.
        let bad = format!("JOB {} audit 8000 stateful_production 0", "aa".repeat(32));
        let Some(Command::Job(job)) = parse_line(&bad).unwrap() else {
            panic!("expected job")
        };
        assert_eq!(
            execute(job.class, &job.spec),
            (
                1,
                hearth_error_code(&HearthError::AvailabilityClassIneligible)
            )
        );
    }

    #[test]
    fn malformed_lines_are_typed_and_never_receipts() {
        for (line, reason) in [
            ("NOPE", "unknown_command"),
            ("JOB zz relay replica 1 40 0", "bad_job_id"),
            (
                "JOB 1111111111111111111111111111111111111111111111111111111111111111 fly x",
                "bad_class",
            ),
            ("SHUTDOWN now", "trailing_tokens"),
        ] {
            assert_eq!(parse_line(line).unwrap_err(), reason, "{line}");
        }
        // Trailing garbage after valid args is also rejected.
        let line = format!("JOB {} relay replica 1 40 0 extra", "ab".repeat(32));
        assert_eq!(parse_line(&line).unwrap_err(), "trailing_tokens");
    }

    #[test]
    fn receipt_body_layout_is_exact_and_domain_separated() {
        let mut worker = Worker::new(&cfg());
        let job_id = [0xab_u8; 32];
        let body = worker.next_receipt_body(&job_id, 1, 0, 4);
        assert_eq!(&body[..32], &[0x22; 32]);
        assert_eq!(&body[32..64], &job_id);
        assert_eq!(&body[64..67], &[1, 0, 4]);
        assert_eq!(&body[67..75], &1_u64.to_le_bytes());
        let sig = worker.sign(&body).unwrap();
        verify_domain(
            DomainId::SigWorkReceipt,
            &worker.public_key(),
            &[&body],
            &sig,
        )
        .unwrap();
        // Falsifier: the same bytes must not verify under a sibling domain.
        assert!(verify_domain(DomainId::SigTx, &worker.public_key(), &[&body], &sig).is_err());
        // Falsifier: a forged body byte must not verify.
        let mut forged = body;
        forged[64] ^= 1;
        assert!(verify_domain(
            DomainId::SigWorkReceipt,
            &worker.public_key(),
            &[&forged],
            &sig
        )
        .is_err());
    }

    #[test]
    fn run_loop_is_deterministic_and_shuts_down_gracefully() {
        let input = format!(
            "JOB {} relay replica 1 40 0\ngarbage line\nJOB {} audit 3000 chorus_advisory 0\nSHUTDOWN\nJOB never reached",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let a = run_to_string(&input, None);
        let b = run_to_string(&input, None);
        assert_eq!(a, b, "two identical runs must be byte-identical");
        assert!(a.ends_with("SHUTDOWN jobs=2 violations=1\n"));
        assert_eq!(
            a.matches("RECEIPT body=").count(),
            2,
            "nothing after SHUTDOWN"
        );
        assert!(a.contains("ERR malformed unknown_command"));
        assert!(a.contains("noos_telemetry_contract_violations_total{reason=\"malformed\"} 1"));
    }

    #[test]
    fn queue_mode_reports_a_decreasing_verifier_backlog() {
        let input = format!(
            "JOB {} audit 3000 chorus_advisory 0\nJOB {} audit 3000 chorus_advisory 0\nSHUTDOWN",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let lines: Vec<String> = input.lines().map(str::to_owned).collect();
        let total = count_job_lines(&lines);
        assert_eq!(total, 2);
        let mut out = Vec::new();
        run(&cfg(), lines.into_iter().map(Ok), Some(total), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
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
            ]
        );
    }
}
