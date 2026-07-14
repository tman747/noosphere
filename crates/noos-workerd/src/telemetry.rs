//! Line-oriented telemetry bound to the frozen telemetry-v1 contract.
//!
//! Every emitted family/label pair below MUST exist in
//! `protocol/telemetry/telemetry-v1.yaml` (validated by
//! `tools/gates/check_telemetry.py`); the conformance test at the bottom of
//! this module re-reads the frozen spec and fails if an emission drifts out
//! of the bounded enums or touches a prohibited label key.

pub mod wwm;

/// Completed jobs, reported as terminal-state NEL jobs.
pub const TERMINAL_JOBS_FAMILY: &str = "noos_nel_finality_state_jobs";
const TERMINAL_JOBS_LABEL_KEY: &str = "state";
const TERMINAL_JOBS_LABEL_VALUE: &str = "terminal";

/// Malformed intake lines, reported as telemetry contract violations.
pub const VIOLATIONS_FAMILY: &str = "noos_telemetry_contract_violations_total";
const VIOLATIONS_LABEL_KEY: &str = "reason";
const VIOLATIONS_LABEL_VALUE: &str = "malformed";

/// Queue-file mode only: JOB lines not yet executed, reported as verifier
/// backlog under the Freivalds profile the audit class runs.
pub const BACKLOG_FAMILY: &str = "noos_nel_verifier_backlog";
const BACKLOG_LABEL_KEY: &str = "profile";
const BACKLOG_LABEL_VALUE: &str = "freivalds_v1";

fn metric_line(family: &str, key: &str, value_label: &str, value: u64) -> String {
    format!("METRIC {family}{{{key}=\"{value_label}\"}} {value}")
}

/// `METRIC noos_nel_finality_state_jobs{state="terminal"} <n>`
#[must_use]
pub fn terminal_jobs_line(count: u64) -> String {
    metric_line(
        TERMINAL_JOBS_FAMILY,
        TERMINAL_JOBS_LABEL_KEY,
        TERMINAL_JOBS_LABEL_VALUE,
        count,
    )
}

/// `METRIC noos_telemetry_contract_violations_total{reason="malformed"} <n>`
#[must_use]
pub fn violations_line(count: u64) -> String {
    metric_line(
        VIOLATIONS_FAMILY,
        VIOLATIONS_LABEL_KEY,
        VIOLATIONS_LABEL_VALUE,
        count,
    )
}

/// `METRIC noos_nel_verifier_backlog{profile="freivalds_v1"} <n>`
#[must_use]
pub fn backlog_line(pending: u64) -> String {
    metric_line(
        BACKLOG_FAMILY,
        BACKLOG_LABEL_KEY,
        BACKLOG_LABEL_VALUE,
        pending,
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use serde_json::Value;

    fn frozen_spec() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/telemetry/telemetry-v1.yaml"
        );
        let text = std::fs::read_to_string(path).expect("read frozen telemetry spec");
        serde_json::from_str(&text).expect("telemetry spec is JSON-form YAML")
    }

    /// Every triple this module can emit, with its family/key/value.
    fn emissions() -> [(&'static str, &'static str, &'static str, String); 3] {
        [
            (
                TERMINAL_JOBS_FAMILY,
                TERMINAL_JOBS_LABEL_KEY,
                TERMINAL_JOBS_LABEL_VALUE,
                terminal_jobs_line(7),
            ),
            (
                VIOLATIONS_FAMILY,
                VIOLATIONS_LABEL_KEY,
                VIOLATIONS_LABEL_VALUE,
                violations_line(7),
            ),
            (
                BACKLOG_FAMILY,
                BACKLOG_LABEL_KEY,
                BACKLOG_LABEL_VALUE,
                backlog_line(7),
            ),
        ]
    }

    #[test]
    fn every_emitted_family_and_label_is_registered_in_the_frozen_spec() {
        let spec = frozen_spec();
        let metrics = spec["metrics"].as_array().unwrap();
        for (family, key, value, line) in emissions() {
            let row = metrics
                .iter()
                .find(|m| m["name"].as_str() == Some(family))
                .unwrap_or_else(|| panic!("{family} missing from frozen telemetry spec"));
            let allowed = row["labels"][key]
                .as_array()
                .unwrap_or_else(|| panic!("{family} has no bounded label key {key}"));
            assert!(
                allowed.iter().any(|v| v.as_str() == Some(value)),
                "{family}: label {key}={value} outside the bounded enum"
            );
            assert_eq!(line, format!("METRIC {family}{{{key}=\"{value}\"}} 7"));
        }
    }

    #[test]
    fn no_emission_uses_a_prohibited_label_key() {
        let spec = frozen_spec();
        let prohibited: Vec<&str> = spec["global_semantics"]["prohibited_labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(!prohibited.is_empty(), "spec must carry prohibited labels");
        for (_, key, _, line) in emissions() {
            assert!(
                !prohibited.contains(&key),
                "label key {key} is prohibited by the telemetry contract"
            );
            // Falsifier shape: a forged line carrying an unbounded job id
            // label would be a contract violation; assert we never emit one.
            for bad in &prohibited {
                assert!(
                    !line.contains(&format!("{bad}=")),
                    "line `{line}` leaks prohibited label {bad}"
                );
            }
        }
    }
}
