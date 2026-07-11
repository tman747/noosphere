//! Chorus retrieval and advisory evidence with lineage/failure-domain quotienting.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub const LIFECYCLE: &str = "EXPERIMENTAL";
pub const RESULT: &str = "ADVISORY_ONLY";
pub const DEFAULT_SLASHABLE: bool = false;
pub const SLASHABLE_AUDITS_ENABLED: bool = false;
pub const MAX_TASK_BYTES: u32 = 1_048_576;
pub const MAX_TASK_STEPS: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskKind {
    Retrieval,
    Advisory,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedTask {
    pub task_id: Hash32,
    pub kind: TaskKind,
    pub commitment: Hash32,
    pub beacon: Hash32,
    pub max_input_bytes: u32,
    pub max_output_bytes: u32,
    pub max_steps: u64,
    pub deadline: u64,
}
impl BoundedTask {
    pub fn derive_id(commitment: Hash32, beacon: Hash32, deadline: u64) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/TASK/V1");
        h.update(&commitment);
        h.update(&beacon);
        h.update(&deadline.to_le_bytes());
        *h.finalize().as_bytes()
    }
    pub fn validate(&self) -> Result<(), ChorusError> {
        if self.beacon == [0; 32]
            || self.commitment == [0; 32]
            || self.task_id != Self::derive_id(self.commitment, self.beacon, self.deadline)
        {
            return Err(ChorusError::PredictableOrMalformed);
        }
        if self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_input_bytes > MAX_TASK_BYTES
            || self.max_output_bytes > MAX_TASK_BYTES
            || self.max_steps == 0
            || self.max_steps > MAX_TASK_STEPS
        {
            return Err(ChorusError::Unbounded);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub task_id: Hash32,
    pub worker: Hash32,
    pub lineage_root: Hash32,
    pub failure_domain: Hash32,
    pub value: i128,
    pub object_root: Hash32,
    pub available: bool,
}
fn quotient_key(e: &Evidence) -> (Hash32, Hash32) {
    (e.lineage_root, e.failure_domain)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub median: i128,
    pub quotient_count: usize,
    pub hidden_copy_limitation: &'static str,
    pub authoritative: bool,
}
/// Each lineage/failure-domain quotient gets one deterministic representative;
/// conflicting members invalidate that quotient rather than multiplying votes.
pub fn advisory(task: &BoundedTask, evidence: &[Evidence]) -> Result<Advisory, ChorusError> {
    task.validate()?;
    let mut groups: BTreeMap<(Hash32, Hash32), BTreeSet<i128>> = BTreeMap::new();
    for e in evidence {
        if e.task_id != task.task_id {
            return Err(ChorusError::WrongTask);
        }
        groups.entry(quotient_key(e)).or_default().insert(e.value);
    }
    let mut values = Vec::new();
    for set in groups.values() {
        if set.len() == 1 {
            values.push(*set.iter().next().ok_or(ChorusError::NoQuotients)?);
        }
    }
    if values.is_empty() {
        return Err(ChorusError::NoQuotients);
    }
    values.sort();
    let median_index = values
        .len()
        .checked_sub(1)
        .and_then(|value| value.checked_div(2))
        .ok_or(ChorusError::NoQuotients)?;
    let median = values[median_index];
    Ok(Advisory {
        median,
        quotient_count: values.len(),
        hidden_copy_limitation: "HIDDEN_COPYING_CANNOT_BE_DETECTED_FROM_DECLARED_LINEAGE",
        authoritative: false,
    })
}
pub const E_ORACLE_01_RESULT: &str = "EXPERIMENTAL_PROFILE";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleReport {
    pub lineage_quotient_median: i128,
    pub quotient_count: usize,
    pub universal_truth: bool,
    pub limitation: &'static str,
}
pub fn oracle_report(
    task: &BoundedTask,
    evidence: &[Evidence],
) -> Result<OracleReport, ChorusError> {
    let result = advisory(task, evidence)?;
    Ok(OracleReport {
        lineage_quotient_median: result.median,
        quotient_count: result.quotient_count,
        universal_truth: false,
        limitation: "HIDDEN_COPIES_OUTSIDE_DECLARED_LINEAGE_REMAIN_UNQUOTIENTED",
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievalResult {
    pub object_root: Hash32,
    pub quotient_count: usize,
    pub advisory_only: bool,
}
pub fn retrieval(
    task: &BoundedTask,
    evidence: &[Evidence],
    minimum_quotients: usize,
) -> Result<RetrievalResult, ChorusError> {
    task.validate()?;
    if task.kind != TaskKind::Retrieval {
        return Err(ChorusError::WrongKind);
    }
    let mut by_object: BTreeMap<Hash32, BTreeSet<(Hash32, Hash32)>> = BTreeMap::new();
    for e in evidence {
        if e.task_id != task.task_id {
            return Err(ChorusError::WrongTask);
        }
        if e.available {
            by_object
                .entry(e.object_root)
                .or_default()
                .insert(quotient_key(e));
        }
    }
    let selected = by_object
        .into_iter()
        .filter(|(_, q)| q.len() >= minimum_quotients)
        .max_by_key(|(root, q)| (q.len(), *root))
        .ok_or(ChorusError::InsufficientDiversity)?;
    Ok(RetrievalResult {
        object_root: selected.0,
        quotient_count: selected.1.len(),
        advisory_only: true,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiversityVerdict {
    AdvisoryEligible,
    HiddenCloneFalsifier,
    ManufacturedThirdFalsifier,
}
pub fn diversity_falsifier(
    total: u64,
    manufactured: u64,
    hidden_clone_detected: bool,
) -> DiversityVerdict {
    if hidden_clone_detected {
        return DiversityVerdict::HiddenCloneFalsifier;
    }
    if total > 0 && u128::from(manufactured) * 3 >= u128::from(total) {
        DiversityVerdict::ManufacturedThirdFalsifier
    } else {
        DiversityVerdict::AdvisoryEligible
    }
}
#[must_use]
pub const fn slash_amount() -> u128 {
    0
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChorusError {
    #[error("task is predictable or malformed")]
    PredictableOrMalformed,
    #[error("task bounds invalid")]
    Unbounded,
    #[error("evidence targets another task")]
    WrongTask,
    #[error("wrong task kind")]
    WrongKind,
    #[error("no valid lineage quotients")]
    NoQuotients,
    #[error("insufficient quotient diversity")]
    InsufficientDiversity,
}
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants
    )]
    use super::*;
    fn h(v: u8) -> Hash32 {
        [v; 32]
    }
    fn task(kind: TaskKind) -> BoundedTask {
        let c = h(1);
        let b = h(2);
        let d = 9;
        BoundedTask {
            task_id: BoundedTask::derive_id(c, b, d),
            kind,
            commitment: c,
            beacon: b,
            max_input_bytes: 10,
            max_output_bytes: 10,
            max_steps: 100,
            deadline: d,
        }
    }
    fn e(t: &BoundedTask, w: u8, l: u8, f: u8, v: i128, o: u8) -> Evidence {
        Evidence {
            task_id: t.task_id,
            worker: h(w),
            lineage_root: h(l),
            failure_domain: h(f),
            value: v,
            object_root: h(o),
            available: true,
        }
    }
    #[test]
    fn duplicate_lineage_is_one_vote() {
        let t = task(TaskKind::Advisory);
        let a = advisory(
            &t,
            &[
                e(&t, 1, 1, 1, 10, 8),
                e(&t, 2, 1, 1, 10, 8),
                e(&t, 3, 2, 2, 30, 8),
            ],
        )
        .unwrap();
        assert_eq!(
            (a.median, a.quotient_count, a.authoritative),
            (10, 2, false)
        );
    }
    #[test]
    fn conflicting_clone_group_is_discarded() {
        let t = task(TaskKind::Advisory);
        let a = advisory(
            &t,
            &[
                e(&t, 1, 1, 1, 10, 8),
                e(&t, 2, 1, 1, 11, 8),
                e(&t, 3, 2, 2, 30, 8),
            ],
        )
        .unwrap();
        assert_eq!((a.median, a.quotient_count), (30, 1));
    }
    #[test]
    fn retrieval_requires_distinct_quotients() {
        let t = task(TaskKind::Retrieval);
        assert_eq!(
            retrieval(&t, &[e(&t, 1, 1, 1, 0, 9), e(&t, 2, 1, 1, 0, 9)], 2),
            Err(ChorusError::InsufficientDiversity)
        );
        let r = retrieval(&t, &[e(&t, 1, 1, 1, 0, 9), e(&t, 2, 2, 2, 0, 9)], 2).unwrap();
        assert_eq!(r.object_root, h(9));
    }
    #[test]
    fn task_bounds_and_unpredictability_fail_closed() {
        let mut t = task(TaskKind::Retrieval);
        t.beacon = [0; 32];
        assert_eq!(t.validate(), Err(ChorusError::PredictableOrMalformed));
        let mut t = task(TaskKind::Retrieval);
        t.max_steps = MAX_TASK_STEPS + 1;
        assert_eq!(t.validate(), Err(ChorusError::Unbounded));
    }
    #[test]
    fn falsifiers_and_slashing_literals() {
        assert_eq!(
            diversity_falsifier(9, 3, false),
            DiversityVerdict::ManufacturedThirdFalsifier
        );
        assert_eq!(
            diversity_falsifier(9, 0, true),
            DiversityVerdict::HiddenCloneFalsifier
        );
        assert!(!DEFAULT_SLASHABLE && !SLASHABLE_AUDITS_ENABLED);
        assert_eq!(slash_amount(), 0);
        assert_eq!((LIFECYCLE, RESULT), ("EXPERIMENTAL", "ADVISORY_ONLY"));
    }
    #[test]
    fn oracle_median_is_explicitly_nonauthoritative() {
        let t = task(TaskKind::Advisory);
        let report = oracle_report(&t, &[e(&t, 1, 1, 1, 5, 8), e(&t, 2, 2, 2, 9, 8)]).unwrap();
        assert_eq!(report.lineage_quotient_median, 5);
        assert!(!report.universal_truth);
        assert_eq!(E_ORACLE_01_RESULT, "EXPERIMENTAL_PROFILE");
        assert!(report.limitation.contains("HIDDEN_COPIES"));
    }
}
