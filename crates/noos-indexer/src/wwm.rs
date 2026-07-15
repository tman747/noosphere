//! Bounded, proof-carrying index projection for canonical WWM economics objects.
//!
//! Finality verification remains in the light resolver. This module consumes the
//! canonical Lumen inclusion proof and object types and only builds named,
//! rebuildable read models. It never scans consensus history during a query.

use noos_codec::NoosEncode;
use noos_lumen::wwm::{
    wwm_profile_key, FundLedgerStatus, FundProfileV1, ResolutionProofV1, ResolutionValueV1,
    WwmEvidenceTier, WwmFundLedgerV1, WwmJobV1, WwmLeafKind, WwmReceiptV1, WwmSettlementV1,
    WwmTerminalCode,
};
use noos_lumen::Hash32;
use noos_work_loom::wwm::{required_free_at, validate_fund_ledger, validate_fund_profile};
use std::collections::{BTreeMap, VecDeque};

pub const MAX_WWM_MUTATIONS_PER_BATCH: usize = 64;
pub const MAX_WWM_REORG_SNAPSHOTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WwmProjectionAnchor {
    pub height: u64,
    pub block_id: Hash32,
    pub parent_block_id: Hash32,
    pub objects_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WwmProjectionError {
    InvalidAnchor,
    BatchTooLarge,
    InvalidProof,
    InvalidObject,
    MissingReference,
    DuplicateTerminalObject,
    UnknownReorgPoint,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WwmIndexedMutation {
    FundProfile {
        value: FundProfileV1,
        proof: ResolutionProofV1,
    },
    FundLedger {
        value: WwmFundLedgerV1,
        proof: ResolutionProofV1,
    },
    Job {
        value: WwmJobV1,
        proof: ResolutionProofV1,
    },
    Receipt {
        value: WwmReceiptV1,
        proof: ResolutionProofV1,
    },
    Settlement {
        value: WwmSettlementV1,
        proof: ResolutionProofV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Proven<T> {
    value: T,
    proof: ResolutionProofV1,
    anchor: WwmProjectionAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WwmFundRowProjection {
    pub bucket: noos_lumen::wwm::FundBucketTag,
    pub baseline_liability_at_origin: u128,
    pub liability_rate_per_height: u128,
    pub coverage_origin_height: u64,
    pub coverage_end_height: u64,
    pub minimum_coverage_heights: u64,
    pub per_reservation_cap: u128,
    pub exposure_cap: u128,
    pub deposits: u128,
    pub migrated_in: u128,
    pub spent: u128,
    pub migrated_out: u128,
    pub reserved: u128,
    pub free: u128,
    pub live_liability: u128,
    pub funded_through_height: Option<u64>,
    pub settlement_index: u64,
    pub required_free_now: Option<u128>,
    pub monetary_headroom: Option<u128>,
    pub runway_blocks: Option<u64>,
    pub alert_days: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WwmFundProofView {
    pub anchor: WwmProjectionAnchor,
    pub profile_id: Hash32,
    pub profile_state_key: Hash32,
    pub ledger_state_key: Hash32,
    pub status: FundLedgerStatus,
    pub topup_permit_epoch: u64,
    pub lock_id: Option<Hash32>,
    pub rows: Vec<WwmFundRowProjection>,
    pub profile_proof: ResolutionProofV1,
    pub ledger_proof: ResolutionProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WwmJobProofView {
    pub anchor: WwmProjectionAnchor,
    pub job: WwmJobV1,
    pub receipt: Option<WwmReceiptV1>,
    pub settlement: Option<WwmSettlementV1>,
    pub job_proof: ResolutionProofV1,
    pub receipt_proof: Option<ResolutionProofV1>,
    pub settlement_proof: Option<ResolutionProofV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WwmProjectionSnapshot {
    head: Option<WwmProjectionAnchor>,
    profiles: BTreeMap<Hash32, Proven<FundProfileV1>>,
    ledgers: BTreeMap<Hash32, Proven<WwmFundLedgerV1>>,
    jobs: BTreeMap<Hash32, Proven<WwmJobV1>>,
    receipts: BTreeMap<Hash32, Proven<WwmReceiptV1>>,
    settlements: BTreeMap<Hash32, Proven<WwmSettlementV1>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WwmEconomicsProjection {
    state: WwmProjectionSnapshot,
    history: VecDeque<WwmProjectionSnapshot>,
}

impl WwmEconomicsProjection {
    pub fn apply_finalized_batch(
        &mut self,
        anchor: WwmProjectionAnchor,
        mutations: &[WwmIndexedMutation],
    ) -> Result<(), WwmProjectionError> {
        if mutations.len() > MAX_WWM_MUTATIONS_PER_BATCH
            || anchor.block_id == [0; 32]
            || anchor.objects_root == [0; 32]
            || self.state.head.is_some_and(|head| {
                anchor.height <= head.height || anchor.parent_block_id != head.block_id
            })
        {
            return Err(if mutations.len() > MAX_WWM_MUTATIONS_PER_BATCH {
                WwmProjectionError::BatchTooLarge
            } else {
                WwmProjectionError::InvalidAnchor
            });
        }
        let mut next = self.state.clone();
        for mutation in mutations {
            match mutation {
                WwmIndexedMutation::FundProfile { value, proof } => {
                    validate_proof(
                        anchor,
                        WwmLeafKind::FundProfile,
                        value.profile_id,
                        value,
                        proof,
                    )?;
                    validate_fund_profile(value, false)
                        .map_err(|_| WwmProjectionError::InvalidObject)?;
                    next.profiles.insert(
                        value.profile_id,
                        Proven {
                            value: value.clone(),
                            proof: proof.clone(),
                            anchor,
                        },
                    );
                }
                WwmIndexedMutation::FundLedger { value, proof } => {
                    validate_proof(
                        anchor,
                        WwmLeafKind::FundLedger,
                        value.profile_id,
                        value,
                        proof,
                    )?;
                    next.ledgers.insert(
                        value.profile_id,
                        Proven {
                            value: value.clone(),
                            proof: proof.clone(),
                            anchor,
                        },
                    );
                }
                WwmIndexedMutation::Job { value, proof } => {
                    validate_proof(anchor, WwmLeafKind::Job, value.job_id, value, proof)?;
                    if value.job_id == [0; 32]
                        || value.fund_profile_id == [0; 32]
                        || value.reserved_amount == 0
                        || value.selected_executor_ids.is_empty()
                    {
                        return Err(WwmProjectionError::InvalidObject);
                    }
                    next.jobs.insert(
                        value.job_id,
                        Proven {
                            value: value.clone(),
                            proof: proof.clone(),
                            anchor,
                        },
                    );
                }
                WwmIndexedMutation::Receipt { value, proof } => {
                    validate_proof(anchor, WwmLeafKind::Receipt, value.receipt_id, value, proof)?;
                    if next.receipts.contains_key(&value.job_id) {
                        return Err(WwmProjectionError::DuplicateTerminalObject);
                    }
                    next.receipts.insert(
                        value.job_id,
                        Proven {
                            value: value.clone(),
                            proof: proof.clone(),
                            anchor,
                        },
                    );
                }
                WwmIndexedMutation::Settlement { value, proof } => {
                    validate_proof(
                        anchor,
                        WwmLeafKind::Settlement,
                        value.settlement_id,
                        value,
                        proof,
                    )?;
                    if next.settlements.contains_key(&value.job_id) {
                        return Err(WwmProjectionError::DuplicateTerminalObject);
                    }
                    next.settlements.insert(
                        value.job_id,
                        Proven {
                            value: value.clone(),
                            proof: proof.clone(),
                            anchor,
                        },
                    );
                }
            }
        }
        validate_cross_references(&next)?;
        next.head = Some(anchor);
        self.state = next.clone();
        self.history.push_back(next);
        while self.history.len() > MAX_WWM_REORG_SNAPSHOTS {
            self.history.pop_front();
        }
        Ok(())
    }

    pub fn rollback_to(&mut self, block_id: Hash32) -> Result<(), WwmProjectionError> {
        let index = self
            .history
            .iter()
            .position(|snapshot| snapshot.head.is_some_and(|head| head.block_id == block_id))
            .ok_or(WwmProjectionError::UnknownReorgPoint)?;
        let snapshot = self
            .history
            .get(index)
            .cloned()
            .ok_or(WwmProjectionError::UnknownReorgPoint)?;
        self.history.truncate(index + 1);
        self.state = snapshot;
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> WwmProjectionSnapshot {
        self.state.clone()
    }

    pub fn restore_snapshot(
        &mut self,
        snapshot: WwmProjectionSnapshot,
    ) -> Result<(), WwmProjectionError> {
        validate_cross_references(&snapshot)?;
        for proven in snapshot.profiles.values() {
            validate_proof(
                proven.anchor,
                WwmLeafKind::FundProfile,
                proven.value.profile_id,
                &proven.value,
                &proven.proof,
            )?;
        }
        for proven in snapshot.ledgers.values() {
            validate_proof(
                proven.anchor,
                WwmLeafKind::FundLedger,
                proven.value.profile_id,
                &proven.value,
                &proven.proof,
            )?;
        }
        self.state = snapshot.clone();
        self.history.clear();
        if snapshot.head.is_some() {
            self.history.push_back(snapshot);
        }
        Ok(())
    }

    pub fn fund_view(
        &self,
        profile_id: Hash32,
        height: u64,
        blocks_per_day: u64,
    ) -> Result<WwmFundProofView, WwmProjectionError> {
        let profile = self
            .state
            .profiles
            .get(&profile_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        let ledger = self
            .state
            .ledgers
            .get(&profile_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        validate_fund_ledger(&profile.value, &ledger.value)
            .map_err(|_| WwmProjectionError::InvalidObject)?;
        if profile.proof.objects_root != ledger.proof.objects_root {
            return Err(WwmProjectionError::InvalidProof);
        }
        let mut rows = Vec::with_capacity(profile.value.coverage_policy_rows.len());
        for (policy, row) in profile
            .value
            .coverage_policy_rows
            .iter()
            .zip(ledger.value.rows.iter())
        {
            let required_free_now = if height >= policy.coverage_origin_height
                && height <= policy.coverage_end_height
            {
                Some(
                    required_free_at(policy, height)
                        .map_err(|_| WwmProjectionError::InvalidObject)?,
                )
            } else {
                None
            };
            let monetary_headroom =
                required_free_now.map(|required| row.free.saturating_sub(required));
            let runway_blocks = row
                .funded_through_height
                .0
                .map(|through| through.saturating_sub(height));
            let mut alert_days = Vec::new();
            if blocks_per_day > 0 {
                if let Some(runway) = runway_blocks {
                    for days in [30_u8, 14, 7, 3, 1] {
                        let threshold = blocks_per_day
                            .checked_mul(u64::from(days))
                            .ok_or(WwmProjectionError::ArithmeticOverflow)?;
                        if runway <= threshold {
                            alert_days.push(days);
                        }
                    }
                } else {
                    alert_days.extend([30, 14, 7, 3, 1]);
                }
            }
            rows.push(WwmFundRowProjection {
                bucket: policy.bucket,
                baseline_liability_at_origin: policy.baseline_liability_at_origin,
                liability_rate_per_height: policy.liability_rate_per_height,
                coverage_origin_height: policy.coverage_origin_height,
                coverage_end_height: policy.coverage_end_height,
                minimum_coverage_heights: policy.minimum_coverage_heights,
                per_reservation_cap: policy.per_reservation_cap,
                exposure_cap: policy.exposure_cap,
                deposits: row.deposits,
                migrated_in: row.migrated_in,
                spent: row.spent,
                migrated_out: row.migrated_out,
                reserved: row.reserved,
                free: row.free,
                live_liability: row.live_liability,
                funded_through_height: row.funded_through_height.0,
                settlement_index: row.settlement_index,
                required_free_now,
                monetary_headroom,
                runway_blocks,
                alert_days,
            });
        }
        Ok(WwmFundProofView {
            anchor: ledger.anchor,
            profile_id,
            profile_state_key: profile.proof.state_key,
            ledger_state_key: ledger.proof.state_key,
            status: ledger.value.status,
            topup_permit_epoch: ledger.value.topup_permit_epoch,
            lock_id: ledger
                .value
                .lock_ref
                .0
                .as_ref()
                .map(|reference| reference.lock_id),
            rows,
            profile_proof: profile.proof.clone(),
            ledger_proof: ledger.proof.clone(),
        })
    }

    pub fn job_view(&self, job_id: Hash32) -> Result<WwmJobProofView, WwmProjectionError> {
        let job = self
            .state
            .jobs
            .get(&job_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        let receipt = self.state.receipts.get(&job_id);
        let settlement = self.state.settlements.get(&job_id);
        Ok(WwmJobProofView {
            anchor: settlement
                .map(|value| value.anchor)
                .or_else(|| receipt.map(|value| value.anchor))
                .unwrap_or(job.anchor),
            job: job.value.clone(),
            receipt: receipt.map(|value| value.value.clone()),
            settlement: settlement.map(|value| value.value.clone()),
            job_proof: job.proof.clone(),
            receipt_proof: receipt.map(|value| value.proof.clone()),
            settlement_proof: settlement.map(|value| value.proof.clone()),
        })
    }

    #[must_use]
    pub fn head(&self) -> Option<WwmProjectionAnchor> {
        self.state.head
    }
}

fn validate_proof<T: NoosEncode>(
    anchor: WwmProjectionAnchor,
    kind: WwmLeafKind,
    id: Hash32,
    value: &T,
    proof: &ResolutionProofV1,
) -> Result<(), WwmProjectionError> {
    let expected_key = wwm_profile_key(kind, &id);
    let encoded = value.encode_canonical();
    let value_matches = match &proof.value {
        ResolutionValueV1::Present(bytes) => bytes.as_slice() == encoded,
        ResolutionValueV1::Absent => false,
    };
    if proof.state_key != expected_key
        || proof.objects_root != anchor.objects_root
        || !value_matches
        || !proof.verify()
    {
        return Err(WwmProjectionError::InvalidProof);
    }
    Ok(())
}

fn validate_cross_references(state: &WwmProjectionSnapshot) -> Result<(), WwmProjectionError> {
    for (profile_id, ledger) in &state.ledgers {
        let profile = state
            .profiles
            .get(profile_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        validate_fund_ledger(&profile.value, &ledger.value)
            .map_err(|_| WwmProjectionError::InvalidObject)?;
    }
    for (job_id, job) in &state.jobs {
        if *job_id != job.value.job_id
            || !state.profiles.contains_key(&job.value.fund_profile_id)
            || !state.ledgers.contains_key(&job.value.fund_profile_id)
        {
            return Err(WwmProjectionError::MissingReference);
        }
    }
    for (job_id, receipt) in &state.receipts {
        let job = state
            .jobs
            .get(job_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        let accounted = receipt
            .value
            .paid_amount
            .checked_add(receipt.value.refunded_amount)
            .ok_or(WwmProjectionError::ArithmeticOverflow)?;
        let terminal_valid = match receipt.value.terminal_code {
            WwmTerminalCode::Complete => matches!(
                receipt.value.evidence_tier,
                WwmEvidenceTier::SignedSingle | WwmEvidenceTier::MatchedQuorum
            ),
            WwmTerminalCode::NoQuorum => {
                receipt.value.evidence_tier == WwmEvidenceTier::NoQuorum
                    && receipt.value.paid_amount == 0
            }
            WwmTerminalCode::Cancelled | WwmTerminalCode::Deadline => {
                receipt.value.paid_amount == 0
            }
            WwmTerminalCode::Rejected => true,
        };
        if receipt.value.job_id != *job_id
            || receipt.value.capsule_id != job.value.capsule_id
            || receipt.value.execution_profile_id != job.value.execution_profile_id
            || receipt.value.receipt_id == [0; 32]
            || receipt.value.signatures.is_empty()
            || accounted > job.value.reserved_amount
            || !terminal_valid
        {
            return Err(WwmProjectionError::InvalidObject);
        }
    }
    for (job_id, settlement) in &state.settlements {
        let job = state
            .jobs
            .get(job_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        let receipt = state
            .receipts
            .get(job_id)
            .ok_or(WwmProjectionError::MissingReference)?;
        let conserved = settlement
            .value
            .paid_amount
            .checked_add(settlement.value.refunded_amount)
            .and_then(|value| value.checked_add(settlement.value.released_amount))
            .ok_or(WwmProjectionError::ArithmeticOverflow)?;
        if settlement.value.job_id != *job_id
            || settlement.value.receipt_id != receipt.value.receipt_id
            || settlement.value.fund_profile_id != job.value.fund_profile_id
            || settlement.value.paid_amount != receipt.value.paid_amount
            || settlement.value.refunded_amount != receipt.value.refunded_amount
            || conserved != job.value.reserved_amount
            || settlement.value.signature.as_slice().is_empty()
        {
            return Err(WwmProjectionError::InvalidObject);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noos_lumen::{
        objects::{BoundedBytes, BoundedList, OptionalObject},
        smt::Smt,
        wwm::{
            genesis_fund_ledger, CoveragePolicyRowV1, FundBucketTag, OptionalU64, SignatureEntryV1,
        },
    };

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn profile(id: Hash32) -> FundProfileV1 {
        let rows = [
            FundBucketTag::Job,
            FundBucketTag::CustodyRetention,
            FundBucketTag::Repair,
            FundBucketTag::ChallengeReferee,
            FundBucketTag::Sponsor,
        ]
        .into_iter()
        .map(|bucket| CoveragePolicyRowV1 {
            bucket,
            baseline_liability_at_origin: 100,
            liability_rate_per_height: 10,
            coverage_origin_height: 10,
            coverage_end_height: 1_000,
            minimum_coverage_heights: 5,
            per_reservation_cap: 1_000,
            exposure_cap: 10_000,
        })
        .collect::<Vec<_>>();
        FundProfileV1 {
            profile_id: id,
            settlement_asset: h(2),
            authority_root: h(3),
            recovery_root: h(4),
            route_root: h(5),
            coverage_policy_rows: BoundedList::new(rows).unwrap(),
            authority_epoch: 1,
            signatures: BoundedList::new(vec![SignatureEntryV1 {
                signer_id: h(6),
                signature: BoundedBytes::new(vec![1; 64]).unwrap(),
            }])
            .unwrap(),
        }
    }

    fn mutations_with_proofs(
        values: Vec<(WwmLeafKind, Hash32, Vec<u8>)>,
        builders: impl FnOnce(Vec<ResolutionProofV1>) -> Vec<WwmIndexedMutation>,
    ) -> (Hash32, Vec<WwmIndexedMutation>) {
        let mut tree = Smt::new();
        for (kind, id, bytes) in &values {
            tree.insert(wwm_profile_key(*kind, id), bytes.clone());
        }
        let root = tree.root();
        let proofs = values
            .iter()
            .map(|(kind, id, bytes)| ResolutionProofV1 {
                state_key: wwm_profile_key(*kind, id),
                value: ResolutionValueV1::Present(BoundedBytes::new(bytes.clone()).unwrap()),
                proof: tree.prove(&wwm_profile_key(*kind, id)),
                objects_root: root,
            })
            .collect();
        (root, builders(proofs))
    }

    #[test]
    fn fund_projection_is_proof_carrying_bounded_and_reorg_replay_exact() {
        let profile = profile(h(10));
        let mut ledger = genesis_fund_ledger(&profile).unwrap();
        let mut rows = ledger.rows.as_slice().to_vec();
        rows[0].deposits = 151;
        rows[0].reserved = 1;
        rows[0].live_liability = 1;
        rows[0].free = 150;
        rows[0].funded_through_height = OptionalU64(Some(15));
        rows[0].settlement_index = 2;
        ledger.rows = BoundedList::new(rows).unwrap();
        ledger.status = FundLedgerStatus::Current;
        ledger.lock_ref = OptionalObject(None);
        let values = vec![
            (
                WwmLeafKind::FundProfile,
                profile.profile_id,
                profile.encode_canonical(),
            ),
            (
                WwmLeafKind::FundLedger,
                ledger.profile_id,
                ledger.encode_canonical(),
            ),
        ];
        let (root, mutations) = mutations_with_proofs(values, |proofs| {
            vec![
                WwmIndexedMutation::FundProfile {
                    value: profile.clone(),
                    proof: proofs[0].clone(),
                },
                WwmIndexedMutation::FundLedger {
                    value: ledger.clone(),
                    proof: proofs[1].clone(),
                },
            ]
        });
        let anchor = WwmProjectionAnchor {
            height: 10,
            block_id: h(11),
            parent_block_id: [0; 32],
            objects_root: root,
        };
        let mut projection = WwmEconomicsProjection::default();
        projection
            .apply_finalized_batch(anchor, &mutations)
            .unwrap();
        let view = projection.fund_view(profile.profile_id, 10, 10).unwrap();
        assert_eq!(view.rows.len(), 5);
        assert_eq!(view.rows[0].required_free_now, Some(100));
        assert_eq!(view.rows[0].monetary_headroom, Some(50));
        assert_eq!(view.rows[0].runway_blocks, Some(5));
        assert_eq!(view.rows[0].live_liability, view.rows[0].reserved);
        assert!(view.profile_proof.verify());
        assert!(view.ledger_proof.verify());

        let snapshot = projection.snapshot();
        let empty_anchor = WwmProjectionAnchor {
            height: 11,
            block_id: h(12),
            parent_block_id: h(11),
            objects_root: root,
        };
        projection.apply_finalized_batch(empty_anchor, &[]).unwrap();
        assert_eq!(projection.head(), Some(empty_anchor));
        projection.rollback_to(h(11)).unwrap();
        assert_eq!(projection.snapshot(), snapshot);
        projection.restore_snapshot(snapshot).unwrap();
        assert_eq!(projection.head(), Some(anchor));
    }

    #[test]
    fn job_receipt_settlement_projection_rejects_double_terminal_and_wrong_proof() {
        let profile = profile(h(20));
        let ledger = genesis_fund_ledger(&profile).unwrap();
        let job = WwmJobV1 {
            job_id: h(21),
            chain_id: h(22),
            genesis_hash: h(23),
            quote_id: h(24),
            registry_epoch: 1,
            client_commitment: h(25),
            capsule_id: h(26),
            execution_profile_id: h(27),
            query_policy_id: h(28),
            max_input_tokens: 100,
            max_output_tokens: 20,
            deadline_height: 100,
            selected_executor_ids: BoundedList::new(vec![h(29)]).unwrap(),
            availability_certificate_id: h(30),
            fund_profile_id: profile.profile_id,
            reserved_amount: 100,
            offchain_envelope_root: h(31),
        };
        let receipt = WwmReceiptV1 {
            receipt_id: h(32),
            job_id: job.job_id,
            capsule_id: job.capsule_id,
            artifact_id: h(33),
            tokenizer_root: h(34),
            template_root: h(35),
            runtime_root: h(36),
            sbom_root: h(37),
            execution_profile_id: job.execution_profile_id,
            input_tokens: 10,
            output_tokens: 5,
            token_history_root: h(38),
            output_root: h(39),
            signer_ids: BoundedList::new(vec![h(29)]).unwrap(),
            control_cluster_ids: BoundedList::new(vec![h(40)]).unwrap(),
            evidence_tier: WwmEvidenceTier::SignedSingle,
            availability_until: 200,
            evidence_until: 200,
            anchor_height: 90,
            anchor_block: h(41),
            metered_amount: 60,
            paid_amount: 60,
            refunded_amount: 40,
            terminal_code: WwmTerminalCode::Complete,
            signatures: BoundedList::new(vec![SignatureEntryV1 {
                signer_id: h(29),
                signature: BoundedBytes::new(vec![2; 64]).unwrap(),
            }])
            .unwrap(),
        };
        let settlement = WwmSettlementV1 {
            settlement_id: h(42),
            job_id: job.job_id,
            receipt_id: receipt.receipt_id,
            fund_profile_id: profile.profile_id,
            bucket: FundBucketTag::Job,
            prior_settlement_index: 1,
            paid_amount: 60,
            refunded_amount: 40,
            released_amount: 0,
            settled_height: 91,
            authority_epoch: 1,
            signature: BoundedBytes::new(vec![3; 64]).unwrap(),
        };
        let values = vec![
            (
                WwmLeafKind::FundProfile,
                profile.profile_id,
                profile.encode_canonical(),
            ),
            (
                WwmLeafKind::FundLedger,
                ledger.profile_id,
                ledger.encode_canonical(),
            ),
            (WwmLeafKind::Job, job.job_id, job.encode_canonical()),
            (
                WwmLeafKind::Receipt,
                receipt.receipt_id,
                receipt.encode_canonical(),
            ),
            (
                WwmLeafKind::Settlement,
                settlement.settlement_id,
                settlement.encode_canonical(),
            ),
        ];
        let (root, mutations) = mutations_with_proofs(values, |proofs| {
            vec![
                WwmIndexedMutation::FundProfile {
                    value: profile,
                    proof: proofs[0].clone(),
                },
                WwmIndexedMutation::FundLedger {
                    value: ledger,
                    proof: proofs[1].clone(),
                },
                WwmIndexedMutation::Job {
                    value: job.clone(),
                    proof: proofs[2].clone(),
                },
                WwmIndexedMutation::Receipt {
                    value: receipt.clone(),
                    proof: proofs[3].clone(),
                },
                WwmIndexedMutation::Settlement {
                    value: settlement.clone(),
                    proof: proofs[4].clone(),
                },
            ]
        });
        let anchor = WwmProjectionAnchor {
            height: 91,
            block_id: h(43),
            parent_block_id: [0; 32],
            objects_root: root,
        };
        let mut projection = WwmEconomicsProjection::default();
        projection
            .apply_finalized_batch(anchor, &mutations)
            .unwrap();
        let view = projection.job_view(job.job_id).unwrap();
        assert_eq!(
            view.receipt.as_ref().map(|value| value.receipt_id),
            Some(receipt.receipt_id)
        );
        assert_eq!(
            view.settlement.as_ref().map(|value| value.settlement_id),
            Some(settlement.settlement_id)
        );

        let duplicate = [WwmIndexedMutation::Settlement {
            value: settlement,
            proof: match &mutations[4] {
                WwmIndexedMutation::Settlement { proof, .. } => proof.clone(),
                _ => unreachable!(),
            },
        }];
        let next_anchor = WwmProjectionAnchor {
            height: 92,
            block_id: h(44),
            parent_block_id: h(43),
            objects_root: root,
        };
        assert_eq!(
            projection.apply_finalized_batch(next_anchor, &duplicate),
            Err(WwmProjectionError::DuplicateTerminalObject)
        );
    }
}
