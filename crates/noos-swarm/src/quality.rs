use crate::{Hash32, SwarmError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const RECEIPT_DOMAIN: &str = "NOOS/QUALITY/RECEIPT/V1";

fn quality_hash(parts: &[&[u8]]) -> Hash32 {
    let mut hash = blake3::Hasher::new();
    hash.update(RECEIPT_DOMAIN.as_bytes());
    for part in parts {
        let length = u32::try_from(part.len()).unwrap_or(u32::MAX);
        hash.update(&length.to_be_bytes());
        hash.update(part);
    }
    *hash.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityReceipt {
    pub receipt_id: Hash32,
    pub task_id: Hash32,
    pub candidate: Hash32,
    pub rubric: Hash32,
    pub evaluator: Hash32,
    pub context_root: Hash32,
    pub score_bps: u16,
    pub safety_critical_reject: bool,
}

impl QualityReceipt {
    #[must_use]
    pub fn derived_id(&self) -> Hash32 {
        quality_hash(&[
            &self.task_id,
            &self.candidate,
            &self.rubric,
            &self.evaluator,
            &self.context_root,
            &self.score_bps.to_be_bytes(),
            &[u8::from(self.safety_critical_reject)],
        ])
    }

    pub fn validate(&self) -> Result<(), SwarmError> {
        if self.task_id == [0; 32]
            || self.candidate == [0; 32]
            || self.rubric == [0; 32]
            || self.evaluator == [0; 32]
            || self.context_root == [0; 32]
            || self.score_bps > 10_000
            || self.receipt_id != self.derived_id()
        {
            Err(SwarmError::InvalidQualityReceipt)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DiversityRegistry {
    evaluator_domains: BTreeMap<Hash32, Hash32>,
}

impl DiversityRegistry {
    pub fn register(
        &mut self,
        evaluator: Hash32,
        control_domain: Hash32,
    ) -> Result<(), SwarmError> {
        if evaluator == [0; 32]
            || control_domain == [0; 32]
            || self.evaluator_domains.contains_key(&evaluator)
        {
            return Err(SwarmError::InvalidDiversityIdentity);
        }
        self.evaluator_domains.insert(evaluator, control_domain);
        Ok(())
    }

    fn domain(&self, evaluator: &Hash32) -> Result<Hash32, SwarmError> {
        self.evaluator_domains
            .get(evaluator)
            .copied()
            .ok_or(SwarmError::UnknownEvaluator)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualityAggregate {
    pub task_id: Hash32,
    pub candidate: Hash32,
    pub rubric: Hash32,
    pub score_bps: u16,
    pub independent_domains: u32,
    pub safety_critical_reject: bool,
}

/// Each attested control domain contributes one conservative score (its
/// minimum receipt), then the aggregate is the median domain score. Splitting
/// one controller into evaluator Sybils cannot increase either value.
pub fn aggregate_quality(
    receipts: &[QualityReceipt],
    diversity: &DiversityRegistry,
) -> Result<QualityAggregate, SwarmError> {
    let first = receipts.first().ok_or(SwarmError::EmptyQualityEvidence)?;
    let mut receipt_ids = BTreeSet::new();
    let mut evaluators = BTreeSet::new();
    let mut domain_scores: BTreeMap<Hash32, u16> = BTreeMap::new();
    let mut safety_critical_reject = false;
    for receipt in receipts {
        receipt.validate()?;
        if receipt.task_id != first.task_id
            || receipt.candidate != first.candidate
            || receipt.rubric != first.rubric
            || !receipt_ids.insert(receipt.receipt_id)
            || !evaluators.insert(receipt.evaluator)
        {
            return Err(SwarmError::SplicedQualityEvidence);
        }
        let domain = diversity.domain(&receipt.evaluator)?;
        domain_scores
            .entry(domain)
            .and_modify(|score| *score = (*score).min(receipt.score_bps))
            .or_insert(receipt.score_bps);
        safety_critical_reject |= receipt.safety_critical_reject;
    }
    let mut scores = domain_scores.values().copied().collect::<Vec<_>>();
    scores.sort_unstable();
    let score_bps = if safety_critical_reject {
        0
    } else {
        let middle = scores
            .len()
            .checked_sub(1)
            .and_then(|value| value.checked_div(2))
            .ok_or(SwarmError::EmptyQualityEvidence)?;
        *scores.get(middle).ok_or(SwarmError::EmptyQualityEvidence)?
    };
    Ok(QualityAggregate {
        task_id: first.task_id,
        candidate: first.candidate,
        rubric: first.rubric,
        score_bps,
        independent_domains: u32::try_from(domain_scores.len())
            .map_err(|_| SwarmError::Overflow)?,
        safety_critical_reject,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualityEscrowState {
    Proposed,
    Escrowed,
    Paid,
    Refunded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualityEscrow {
    pub escrow_id: Hash32,
    pub task_id: Hash32,
    pub evaluator: Hash32,
    pub amount: u128,
    pub deadline: u64,
    pub state: QualityEscrowState,
    pub paid_receipt: Option<Hash32>,
}

impl QualityEscrow {
    pub fn fund(&mut self) -> Result<(), SwarmError> {
        if self.state != QualityEscrowState::Proposed || self.amount == 0 {
            return Err(SwarmError::InvalidTransition);
        }
        self.state = QualityEscrowState::Escrowed;
        Ok(())
    }

    pub fn pay(&mut self, receipt: &QualityReceipt, height: u64) -> Result<(), SwarmError> {
        receipt.validate()?;
        if self.state != QualityEscrowState::Escrowed
            || height > self.deadline
            || receipt.task_id != self.task_id
            || receipt.evaluator != self.evaluator
            || self.paid_receipt.is_some()
        {
            return Err(SwarmError::InvalidTransition);
        }
        self.paid_receipt = Some(receipt.receipt_id);
        self.state = QualityEscrowState::Paid;
        Ok(())
    }

    pub fn refund_expired(&mut self, height: u64) -> Result<(), SwarmError> {
        if self.state != QualityEscrowState::Escrowed || height <= self.deadline {
            return Err(SwarmError::InvalidTransition);
        }
        self.state = QualityEscrowState::Refunded;
        Ok(())
    }

    #[must_use]
    pub fn terminal_or_refundable(&self, height: u64) -> bool {
        matches!(
            self.state,
            QualityEscrowState::Paid | QualityEscrowState::Refunded
        ) || (self.state == QualityEscrowState::Escrowed && height > self.deadline)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn receipt(evaluator: u8, score_bps: u16, reject: bool) -> QualityReceipt {
        let mut receipt = QualityReceipt {
            receipt_id: [0; 32],
            task_id: h(1),
            candidate: h(2),
            rubric: h(3),
            evaluator: h(evaluator),
            context_root: h(4),
            score_bps,
            safety_critical_reject: reject,
        };
        receipt.receipt_id = receipt.derived_id();
        receipt
    }

    #[test]
    fn claim_quality_sybil_evaluators_cannot_inflate_domain_or_median() {
        let mut diversity = DiversityRegistry::default();
        diversity.register(h(10), h(40)).unwrap();
        diversity.register(h(11), h(50)).unwrap();
        diversity.register(h(12), h(60)).unwrap();
        let baseline = aggregate_quality(
            &[
                receipt(10, 2_000, false),
                receipt(11, 7_000, false),
                receipt(12, 8_000, false),
            ],
            &diversity,
        )
        .unwrap();
        assert_eq!(baseline.score_bps, 7_000);

        for evaluator in 20..40 {
            diversity.register(h(evaluator), h(40)).unwrap();
        }
        let mut sybil_receipts = vec![
            receipt(10, 2_000, false),
            receipt(11, 7_000, false),
            receipt(12, 8_000, false),
        ];
        sybil_receipts.extend((20..40).map(|evaluator| receipt(evaluator, 10_000, false)));
        let attacked = aggregate_quality(&sybil_receipts, &diversity).unwrap();
        assert_eq!(attacked.score_bps, baseline.score_bps);
        assert_eq!(attacked.independent_domains, baseline.independent_domains);
    }

    #[test]
    fn claim_quality_safety_reject_is_veto_and_receipt_splice_rejects() {
        let mut diversity = DiversityRegistry::default();
        diversity.register(h(10), h(40)).unwrap();
        diversity.register(h(11), h(50)).unwrap();
        let aggregate = aggregate_quality(
            &[receipt(10, 10_000, false), receipt(11, 9_000, true)],
            &diversity,
        )
        .unwrap();
        assert!(aggregate.safety_critical_reject);
        assert_eq!(aggregate.score_bps, 0);

        let good = receipt(10, 5_000, false);
        let mut spliced = receipt(11, 5_000, false);
        spliced.task_id = h(99);
        spliced.receipt_id = spliced.derived_id();
        assert_eq!(
            aggregate_quality(&[good, spliced], &diversity),
            Err(SwarmError::SplicedQualityEvidence)
        );
    }

    #[test]
    fn claim_quality_escrow_has_no_double_pay_or_trapped_expiry() {
        let receipt = receipt(10, 5_000, false);
        let mut escrow = QualityEscrow {
            escrow_id: h(70),
            task_id: h(1),
            evaluator: h(10),
            amount: 100,
            deadline: 10,
            state: QualityEscrowState::Proposed,
            paid_receipt: None,
        };
        escrow.fund().unwrap();
        escrow.pay(&receipt, 10).unwrap();
        assert_eq!(escrow.pay(&receipt, 10), Err(SwarmError::InvalidTransition));

        let mut expired = QualityEscrow {
            state: QualityEscrowState::Proposed,
            paid_receipt: None,
            ..escrow
        };
        expired.fund().unwrap();
        assert!(expired.terminal_or_refundable(11));
        expired.refund_expired(11).unwrap();
        assert_eq!(expired.state, QualityEscrowState::Refunded);
    }
}
