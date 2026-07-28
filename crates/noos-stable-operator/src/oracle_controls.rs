//! Production oracle admission, rotation, rejection telemetry, and
//! operation-specific conservative pricing.
//!
//! The control plane keeps exactly five independently identified reporters.
//! Updates are staged before mutation, quorum medians cannot jump outside the
//! configured deviation bound, and an explicit frozen mode never auto-unfreezes.

pub type Hash32 = [u8; 32];

pub const REPORTER_COUNT: usize = 5;
pub const REPORTER_QUORUM: usize = 3;
const BASIS_POINTS: u128 = 10_000;
const REJECTION_REASON_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleControlError {
    InvalidPolicy,
    InvalidReporterSet,
    RotationPending,
    NoRotationPending,
    RotationTimelocked,
    UnauthorizedReporter,
    ReplayedReport,
    InvalidReport,
    StaleReport,
    ExcessiveDeviation,
    NoQuorum,
    Frozen,
    LastGoodUnavailable,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    UnauthorizedReporter,
    ReplayedReport,
    InvalidReport,
    StaleReport,
    ExcessiveDeviation,
}

impl RejectionReason {
    const fn index(self) -> usize {
        match self {
            Self::UnauthorizedReporter => 0,
            Self::ReplayedReport => 1,
            Self::InvalidReport => 2,
            Self::StaleReport => 3,
            Self::ExcessiveDeviation => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReporterIdentity {
    pub reporter: Hash32,
    pub operator: Hash32,
    pub provider: Hash32,
    pub region: Hash32,
}

impl ReporterIdentity {
    fn validate(self) -> Result<(), OracleControlError> {
        if [self.reporter, self.operator, self.provider, self.region].contains(&[0; 32]) {
            return Err(OracleControlError::InvalidReporterSet);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReporterSet {
    pub epoch: u64,
    pub members: [ReporterIdentity; REPORTER_COUNT],
}

impl ReporterSet {
    pub fn validate(self) -> Result<(), OracleControlError> {
        if self.epoch == 0 {
            return Err(OracleControlError::InvalidReporterSet);
        }
        for (index, member) in self.members.iter().copied().enumerate() {
            member.validate()?;
            for prior in &self.members[..index] {
                if member.reporter == prior.reporter || member.operator == prior.operator {
                    return Err(OracleControlError::InvalidReporterSet);
                }
            }
            let provider_count = self
                .members
                .iter()
                .filter(|candidate| candidate.provider == member.provider)
                .count();
            let region_count = self
                .members
                .iter()
                .filter(|candidate| candidate.region == member.region)
                .count();
            if provider_count > 2 || region_count > 2 {
                return Err(OracleControlError::InvalidReporterSet);
            }
        }
        Ok(())
    }

    fn reporter_index(&self, reporter: &Hash32) -> Option<usize> {
        self.members
            .iter()
            .position(|member| member.reporter == *reporter)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleControlPolicy {
    pub max_report_age_blocks: u64,
    pub max_last_good_age_blocks: u64,
    pub max_deviation_bps: u16,
    pub max_confidence_bps: u16,
    pub operation_buffer_bps: u16,
    pub minimum_rotation_delay_blocks: u64,
}

impl OracleControlPolicy {
    pub fn validate(self) -> Result<(), OracleControlError> {
        if self.max_report_age_blocks == 0
            || self.max_last_good_age_blocks < self.max_report_age_blocks
            || !(1..=2_000).contains(&self.max_deviation_bps)
            || self.max_confidence_bps > 1_000
            || self.operation_buffer_bps > 2_000
            || self.minimum_rotation_delay_blocks == 0
        {
            return Err(OracleControlError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleMode {
    Live,
    LastGood,
    Frozen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleOperation {
    Borrow,
    WithdrawCollateral,
    Liquidate,
    PsmMint,
    PsmRedeem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedReport {
    pub reporter: Hash32,
    pub price_q9: u128,
    pub confidence_bps: u16,
    pub sequence: u64,
    pub observed_height: u64,
    pub accepted_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    PendingQuorum { fresh_reports: u8 },
    QuorumAccepted { median_price_q9: u128 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    pub reporters: ReporterSet,
    pub activation_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejectedUpdateMonitor {
    pub total: u64,
    pub by_reason: [u64; REJECTION_REASON_COUNT],
    pub last_reason: Option<RejectionReason>,
    pub last_reporter: Hash32,
    pub last_height: u64,
}

impl Default for RejectedUpdateMonitor {
    fn default() -> Self {
        Self {
            total: 0,
            by_reason: [0; REJECTION_REASON_COUNT],
            last_reason: None,
            last_reporter: [0; 32],
            last_height: 0,
        }
    }
}

impl RejectedUpdateMonitor {
    fn record(&mut self, reason: RejectionReason, reporter: Hash32, height: u64) {
        // Monitoring must never turn a rejected update into an availability
        // failure. Counters therefore pin at u64::MAX while the latest reason,
        // reporter, and height continue to advance.
        self.total = self.total.saturating_add(1);
        self.by_reason[reason.index()] = self.by_reason[reason.index()].saturating_add(1);
        self.last_reason = Some(reason);
        self.last_reporter = reporter;
        self.last_height = height;
    }

    #[must_use]
    pub const fn count(self, reason: RejectionReason) -> u64 {
        self.by_reason[reason.index()]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastGoodPrice {
    pub price_q9: u128,
    pub height: u64,
}

pub struct OracleControlPlane {
    policy: OracleControlPolicy,
    reporters: ReporterSet,
    pending_rotation: Option<RotationPlan>,
    reports: [Option<AcceptedReport>; REPORTER_COUNT],
    last_sequences: [u64; REPORTER_COUNT],
    last_good: Option<LastGoodPrice>,
    mode: OracleMode,
    rejected: RejectedUpdateMonitor,
}

impl OracleControlPlane {
    pub fn new(
        policy: OracleControlPolicy,
        reporters: ReporterSet,
    ) -> Result<Self, OracleControlError> {
        policy.validate()?;
        reporters.validate()?;
        Ok(Self {
            policy,
            reporters,
            pending_rotation: None,
            reports: [None; REPORTER_COUNT],
            last_sequences: [0; REPORTER_COUNT],
            last_good: None,
            mode: OracleMode::Live,
            rejected: RejectedUpdateMonitor::default(),
        })
    }

    #[must_use]
    pub const fn reporter_set(&self) -> ReporterSet {
        self.reporters
    }

    #[must_use]
    pub const fn pending_rotation(&self) -> Option<RotationPlan> {
        self.pending_rotation
    }

    #[must_use]
    pub const fn mode(&self) -> OracleMode {
        self.mode
    }

    #[must_use]
    pub const fn last_good(&self) -> Option<LastGoodPrice> {
        self.last_good
    }

    #[must_use]
    pub const fn rejected_updates(&self) -> RejectedUpdateMonitor {
        self.rejected
    }

    pub fn set_mode(&mut self, mode: OracleMode) -> Result<(), OracleControlError> {
        if mode == OracleMode::LastGood && self.last_good.is_none() {
            return Err(OracleControlError::LastGoodUnavailable);
        }
        self.mode = mode;
        Ok(())
    }

    pub fn schedule_rotation(
        &mut self,
        reporters: ReporterSet,
        current_height: u64,
        activation_height: u64,
    ) -> Result<(), OracleControlError> {
        if self.pending_rotation.is_some() {
            return Err(OracleControlError::RotationPending);
        }
        reporters.validate()?;
        let expected_epoch = self
            .reporters
            .epoch
            .checked_add(1)
            .ok_or(OracleControlError::ArithmeticOverflow)?;
        let earliest = current_height
            .checked_add(self.policy.minimum_rotation_delay_blocks)
            .ok_or(OracleControlError::ArithmeticOverflow)?;
        if reporters.epoch != expected_epoch || activation_height < earliest {
            return Err(OracleControlError::RotationTimelocked);
        }
        self.pending_rotation = Some(RotationPlan {
            reporters,
            activation_height,
        });
        Ok(())
    }

    pub fn activate_rotation(&mut self, current_height: u64) -> Result<(), OracleControlError> {
        let plan = self
            .pending_rotation
            .ok_or(OracleControlError::NoRotationPending)?;
        if current_height < plan.activation_height {
            return Err(OracleControlError::RotationTimelocked);
        }
        self.reporters = plan.reporters;
        self.pending_rotation = None;
        self.reports = [None; REPORTER_COUNT];
        self.last_sequences = [0; REPORTER_COUNT];
        self.mode = if self.last_good.is_some() {
            OracleMode::LastGood
        } else {
            OracleMode::Live
        };
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_report(
        &mut self,
        reporter: Hash32,
        price_q9: u128,
        confidence_bps: u16,
        sequence: u64,
        observed_height: u64,
        current_height: u64,
    ) -> Result<UpdateOutcome, OracleControlError> {
        let Some(index) = self.reporters.reporter_index(&reporter) else {
            return self.reject(
                RejectionReason::UnauthorizedReporter,
                reporter,
                current_height,
                OracleControlError::UnauthorizedReporter,
            );
        };
        if price_q9 == 0 || confidence_bps > self.policy.max_confidence_bps || sequence == 0 {
            return self.reject(
                RejectionReason::InvalidReport,
                reporter,
                current_height,
                OracleControlError::InvalidReport,
            );
        }
        if observed_height > current_height
            || current_height.saturating_sub(observed_height) > self.policy.max_report_age_blocks
        {
            return self.reject(
                RejectionReason::StaleReport,
                reporter,
                current_height,
                OracleControlError::StaleReport,
            );
        }
        if sequence <= self.last_sequences[index] {
            return self.reject(
                RejectionReason::ReplayedReport,
                reporter,
                current_height,
                OracleControlError::ReplayedReport,
            );
        }

        let mut candidate_reports = self.reports;
        candidate_reports[index] = Some(AcceptedReport {
            reporter,
            price_q9,
            confidence_bps,
            sequence,
            observed_height,
            accepted_height: current_height,
        });
        let (fresh_reports, median) = fresh_median(
            &candidate_reports,
            current_height,
            self.policy.max_report_age_blocks,
        );
        if let Some(median_price_q9) = median {
            if let Some(last_good) = self.last_good {
                if deviation_bps(median_price_q9, last_good.price_q9)?
                    > u128::from(self.policy.max_deviation_bps)
                {
                    return self.reject(
                        RejectionReason::ExcessiveDeviation,
                        reporter,
                        current_height,
                        OracleControlError::ExcessiveDeviation,
                    );
                }
            }
            self.reports = candidate_reports;
            self.last_sequences[index] = sequence;
            self.last_good = Some(LastGoodPrice {
                price_q9: median_price_q9,
                height: current_height,
            });
            if self.mode != OracleMode::Frozen {
                self.mode = OracleMode::Live;
            }
            return Ok(UpdateOutcome::QuorumAccepted { median_price_q9 });
        }

        self.reports = candidate_reports;
        self.last_sequences[index] = sequence;
        Ok(UpdateOutcome::PendingQuorum {
            fresh_reports: u8::try_from(fresh_reports)
                .map_err(|_| OracleControlError::ArithmeticOverflow)?,
        })
    }

    pub fn operation_price(
        &self,
        operation: OracleOperation,
        current_height: u64,
    ) -> Result<u128, OracleControlError> {
        if self.mode == OracleMode::Frozen {
            return Err(OracleControlError::Frozen);
        }
        let last_good = self
            .last_good
            .ok_or(OracleControlError::LastGoodUnavailable)?;
        let maximum_age = match self.mode {
            OracleMode::Live => self.policy.max_report_age_blocks,
            OracleMode::LastGood => self.policy.max_last_good_age_blocks,
            OracleMode::Frozen => return Err(OracleControlError::Frozen),
        };
        if current_height < last_good.height
            || current_height.saturating_sub(last_good.height) > maximum_age
        {
            return Err(OracleControlError::LastGoodUnavailable);
        }
        if self.mode == OracleMode::LastGood
            && !matches!(
                operation,
                OracleOperation::Liquidate | OracleOperation::PsmRedeem
            )
        {
            return Err(OracleControlError::Frozen);
        }
        match operation {
            OracleOperation::Borrow
            | OracleOperation::WithdrawCollateral
            | OracleOperation::PsmMint => {
                buffered_lower_price(last_good.price_q9, self.policy.operation_buffer_bps)
            }
            OracleOperation::Liquidate | OracleOperation::PsmRedeem => {
                buffered_upper_price(last_good.price_q9, self.policy.operation_buffer_bps)
            }
        }
    }

    fn reject<T>(
        &mut self,
        reason: RejectionReason,
        reporter: Hash32,
        height: u64,
        error: OracleControlError,
    ) -> Result<T, OracleControlError> {
        self.rejected.record(reason, reporter, height);
        Err(error)
    }
}

fn fresh_median(
    reports: &[Option<AcceptedReport>; REPORTER_COUNT],
    current_height: u64,
    max_age_blocks: u64,
) -> (usize, Option<u128>) {
    let mut prices = [0_u128; REPORTER_COUNT];
    let mut count = 0_usize;
    for report in reports.iter().flatten() {
        if report.observed_height <= current_height
            && current_height.saturating_sub(report.observed_height) <= max_age_blocks
        {
            prices[count] = report.price_q9;
            count += 1;
        }
    }
    if count < REPORTER_QUORUM {
        return (count, None);
    }
    prices[..count].sort_unstable();
    (count, Some(prices[count / 2]))
}

fn deviation_bps(candidate: u128, reference: u128) -> Result<u128, OracleControlError> {
    if reference == 0 {
        return Err(OracleControlError::InvalidReport);
    }
    candidate
        .abs_diff(reference)
        .checked_mul(BASIS_POINTS)
        .and_then(|scaled| scaled.checked_div(reference))
        .ok_or(OracleControlError::ArithmeticOverflow)
}

fn buffered_lower_price(price: u128, buffer_bps: u16) -> Result<u128, OracleControlError> {
    price
        .checked_mul(BASIS_POINTS - u128::from(buffer_bps))
        .and_then(|scaled| scaled.checked_div(BASIS_POINTS))
        .ok_or(OracleControlError::ArithmeticOverflow)
}

fn buffered_upper_price(price: u128, buffer_bps: u16) -> Result<u128, OracleControlError> {
    price
        .checked_mul(BASIS_POINTS + u128::from(buffer_bps))
        .map(|scaled| scaled.div_ceil(BASIS_POINTS))
        .ok_or(OracleControlError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn reporters(first: u8, epoch: u64) -> ReporterSet {
        ReporterSet {
            epoch,
            members: [
                ReporterIdentity {
                    reporter: h(first),
                    operator: h(first + 20),
                    provider: h(60),
                    region: h(70),
                },
                ReporterIdentity {
                    reporter: h(first + 1),
                    operator: h(first + 21),
                    provider: h(60),
                    region: h(70),
                },
                ReporterIdentity {
                    reporter: h(first + 2),
                    operator: h(first + 22),
                    provider: h(61),
                    region: h(71),
                },
                ReporterIdentity {
                    reporter: h(first + 3),
                    operator: h(first + 23),
                    provider: h(61),
                    region: h(71),
                },
                ReporterIdentity {
                    reporter: h(first + 4),
                    operator: h(first + 24),
                    provider: h(62),
                    region: h(72),
                },
            ],
        }
    }

    fn policy() -> OracleControlPolicy {
        OracleControlPolicy {
            max_report_age_blocks: 10,
            max_last_good_age_blocks: 100,
            max_deviation_bps: 500,
            max_confidence_bps: 100,
            operation_buffer_bps: 200,
            minimum_rotation_delay_blocks: 20,
        }
    }

    fn live_plane() -> OracleControlPlane {
        OracleControlPlane::new(policy(), reporters(1, 1)).unwrap()
    }

    fn establish_quorum(plane: &mut OracleControlPlane) {
        assert_eq!(
            plane.submit_report(h(1), 1_000, 10, 1, 10, 10),
            Ok(UpdateOutcome::PendingQuorum { fresh_reports: 1 })
        );
        assert_eq!(
            plane.submit_report(h(2), 1_010, 10, 1, 10, 10),
            Ok(UpdateOutcome::PendingQuorum { fresh_reports: 2 })
        );
        assert_eq!(
            plane.submit_report(h(3), 990, 10, 1, 10, 10),
            Ok(UpdateOutcome::QuorumAccepted {
                median_price_q9: 1_000
            })
        );
    }

    #[test]
    fn independent_set_rejects_operator_and_concentration_collisions() {
        let mut duplicate_operator = reporters(1, 1);
        duplicate_operator.members[1].operator = duplicate_operator.members[0].operator;
        assert_eq!(
            duplicate_operator.validate(),
            Err(OracleControlError::InvalidReporterSet)
        );

        let mut concentrated = reporters(1, 1);
        concentrated.members[2].provider = concentrated.members[0].provider;
        assert_eq!(
            concentrated.validate(),
            Err(OracleControlError::InvalidReporterSet)
        );
    }

    #[test]
    fn quorum_prices_each_operation_conservatively() {
        let mut plane = live_plane();
        establish_quorum(&mut plane);
        assert_eq!(plane.operation_price(OracleOperation::Borrow, 10), Ok(980));
        assert_eq!(
            plane.operation_price(OracleOperation::WithdrawCollateral, 10),
            Ok(980)
        );
        assert_eq!(plane.operation_price(OracleOperation::PsmMint, 10), Ok(980));
        assert_eq!(
            plane.operation_price(OracleOperation::Liquidate, 10),
            Ok(1_020)
        );
        assert_eq!(
            plane.operation_price(OracleOperation::PsmRedeem, 10),
            Ok(1_020)
        );
    }

    #[test]
    fn last_good_is_bounded_and_allows_only_liquidation_and_redemption() {
        let mut plane = live_plane();
        establish_quorum(&mut plane);
        plane.set_mode(OracleMode::LastGood).unwrap();
        assert_eq!(
            plane.operation_price(OracleOperation::Borrow, 50),
            Err(OracleControlError::Frozen)
        );
        assert_eq!(
            plane.operation_price(OracleOperation::Liquidate, 50),
            Ok(1_020)
        );
        assert_eq!(
            plane.operation_price(OracleOperation::PsmRedeem, 50),
            Ok(1_020)
        );
        assert_eq!(
            plane.operation_price(OracleOperation::PsmRedeem, 111),
            Err(OracleControlError::LastGoodUnavailable)
        );
        plane.set_mode(OracleMode::Frozen).unwrap();
        assert_eq!(
            plane.operation_price(OracleOperation::Liquidate, 50),
            Err(OracleControlError::Frozen)
        );
    }

    #[test]
    fn deviation_replay_staleness_and_unknown_reporters_are_counted() {
        let mut plane = live_plane();
        establish_quorum(&mut plane);
        plane.submit_report(h(1), 2_000, 10, 2, 11, 11).unwrap();
        assert_eq!(
            plane.submit_report(h(2), 2_000, 10, 2, 11, 11),
            Err(OracleControlError::ExcessiveDeviation)
        );
        assert_eq!(
            plane.submit_report(h(1), 2_000, 10, 2, 11, 11),
            Err(OracleControlError::ReplayedReport)
        );
        assert_eq!(
            plane.submit_report(h(3), 1_000, 10, 2, 1, 20),
            Err(OracleControlError::StaleReport)
        );
        assert_eq!(
            plane.submit_report(h(99), 1_000, 10, 1, 20, 20),
            Err(OracleControlError::UnauthorizedReporter)
        );
        let rejected = plane.rejected_updates();
        assert_eq!(rejected.total, 4);
        assert_eq!(rejected.count(RejectionReason::ExcessiveDeviation), 1);
        assert_eq!(rejected.count(RejectionReason::ReplayedReport), 1);
        assert_eq!(rejected.count(RejectionReason::StaleReport), 1);
        assert_eq!(rejected.count(RejectionReason::UnauthorizedReporter), 1);
        assert_eq!(plane.last_good().unwrap().price_q9, 1_010);
    }

    #[test]
    fn reporter_rotation_is_delayed_and_clears_replay_domain() {
        let mut plane = live_plane();
        establish_quorum(&mut plane);
        assert_eq!(
            plane.schedule_rotation(reporters(6, 2), 100, 119),
            Err(OracleControlError::RotationTimelocked)
        );
        plane.schedule_rotation(reporters(6, 2), 100, 120).unwrap();
        assert_eq!(
            plane.activate_rotation(119),
            Err(OracleControlError::RotationTimelocked)
        );
        plane.activate_rotation(120).unwrap();
        assert_eq!(plane.reporter_set().epoch, 2);
        assert_eq!(plane.mode(), OracleMode::LastGood);
        assert_eq!(
            plane.submit_report(h(1), 1_000, 10, 2, 120, 120),
            Err(OracleControlError::UnauthorizedReporter)
        );
        assert_eq!(
            plane.submit_report(h(6), 1_000, 10, 1, 120, 120),
            Ok(UpdateOutcome::PendingQuorum { fresh_reports: 1 })
        );
    }
}
