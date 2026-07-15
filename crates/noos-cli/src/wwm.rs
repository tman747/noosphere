//! Typed protocol-v2 WWM action and transaction-carrier builders.
//!
//! User-facing command parsing lives in `wwm_client`; this module accepts only
//! already-typed consensus objects and delegates canonical bytes to noos-lumen.

use crate::{CliError, Result};
use noos_codec::NoosEncode;
use noos_lumen::{
    objects::{ActionV1, BoundedBytes, BoundedList, TransactionV1, TransactionWitnessesV1},
    wwm::{
        carrier_len_valid, ArtifactDescriptorV1, ArtifactRepairPayloadV1,
        AvailabilityCertificateV2, AvailabilityPolicyV2, CapabilityMutationV1,
        CustodianCapabilityMutationV2, CustodyChallengeV2, CustodyPositionCommitmentV2,
        CustodyProbeV2, ExecutionProfileV1, FeePolicyV1, ModelCapsuleV2, QueryPolicyV1,
        RegisterFundProfilePayloadV1, ServiceDirectoryV1, ServingAliasTransitionV1,
        TransitionWwmControlPayloadV1, WwmJobV1, WwmReceiptV1, WwmSettlementV1,
        MAX_TX_WITNESS_BYTES,
    },
};

/// Canonically encode one typed WWM action into the existing bounded action slot.
pub fn encode_wwm_action(action: ActionV1) -> Result<BoundedBytes<65536>> {
    if !is_wwm_action(&action) {
        return Err(CliError::Malformed(
            "expected protocol-v2 WWM action".into(),
        ));
    }
    BoundedBytes::new(action.encode_canonical())
        .ok_or_else(|| CliError::Malformed("WWM action exceeds 65,536-byte action bound".into()))
}

#[must_use]
pub fn is_wwm_action(action: &ActionV1) -> bool {
    matches!(
        action,
        ActionV1::RegisterArtifactDescriptor(_)
            | ActionV1::RegisterCustodianProfile(_)
            | ActionV1::RegisterAvailabilityPolicy(_)
            | ActionV1::CommitCustodyPositions(_)
            | ActionV1::RecordCustodyChallenge(_)
            | ActionV1::RecordCustodyProbe(_)
            | ActionV1::IssueAvailabilityCertificate(_)
            | ActionV1::RecordArtifactRepair(_)
            | ActionV1::RegisterModelCapsuleV2(_)
            | ActionV1::RegisterExecutionProfile(_)
            | ActionV1::RegisterExecutorProfile(_)
            | ActionV1::RegisterFeePolicy(_)
            | ActionV1::RegisterFundProfile(_)
            | ActionV1::RegisterQueryPolicy(_)
            | ActionV1::RegisterServiceDirectory(_)
            | ActionV1::OpenWwmJob(_)
            | ActionV1::RecordWwmReceipt(_)
            | ActionV1::SettleWwmJob(_)
            | ActionV1::TransitionServingAlias(_)
            | ActionV1::TransitionWwmControl(_)
    )
}

macro_rules! typed_builder {
    ($name:ident, $ty:ty, $variant:ident) => {
        pub fn $name(payload: $ty) -> Result<BoundedBytes<65536>> {
            encode_wwm_action(ActionV1::$variant(payload))
        }
    };
}

typed_builder!(
    register_artifact_descriptor,
    ArtifactDescriptorV1,
    RegisterArtifactDescriptor
);
typed_builder!(
    register_custodian_profile,
    CustodianCapabilityMutationV2,
    RegisterCustodianProfile
);
typed_builder!(
    register_availability_policy,
    AvailabilityPolicyV2,
    RegisterAvailabilityPolicy
);
typed_builder!(
    commit_custody_positions,
    CustodyPositionCommitmentV2,
    CommitCustodyPositions
);
typed_builder!(
    record_custody_challenge,
    CustodyChallengeV2,
    RecordCustodyChallenge
);
typed_builder!(record_custody_probe, CustodyProbeV2, RecordCustodyProbe);
typed_builder!(
    issue_availability_certificate,
    AvailabilityCertificateV2,
    IssueAvailabilityCertificate
);
typed_builder!(
    record_artifact_repair,
    ArtifactRepairPayloadV1,
    RecordArtifactRepair
);
typed_builder!(
    register_model_capsule_v2,
    ModelCapsuleV2,
    RegisterModelCapsuleV2
);
typed_builder!(
    register_execution_profile,
    ExecutionProfileV1,
    RegisterExecutionProfile
);
typed_builder!(
    register_executor_profile,
    CapabilityMutationV1,
    RegisterExecutorProfile
);
typed_builder!(register_fee_policy, FeePolicyV1, RegisterFeePolicy);
typed_builder!(
    register_fund_profile,
    RegisterFundProfilePayloadV1,
    RegisterFundProfile
);
typed_builder!(register_query_policy, QueryPolicyV1, RegisterQueryPolicy);
typed_builder!(
    register_service_directory,
    ServiceDirectoryV1,
    RegisterServiceDirectory
);
typed_builder!(open_wwm_job, WwmJobV1, OpenWwmJob);
typed_builder!(record_wwm_receipt, WwmReceiptV1, RecordWwmReceipt);
typed_builder!(settle_wwm_job, WwmSettlementV1, SettleWwmJob);
typed_builder!(
    transition_serving_alias,
    ServingAliasTransitionV1,
    TransitionServingAlias
);
typed_builder!(
    transition_wwm_control,
    TransitionWwmControlPayloadV1,
    TransitionWwmControl
);
/// Exact three-step WWM job lifecycle accepted by the devnet/test operator.
///
/// This is an operator-side binding check, not a new consensus object. Each
/// member is encoded through the already-frozen protocol-v2 action variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevnetWwmFlowV1 {
    pub job: WwmJobV1,
    pub receipt: WwmReceiptV1,
    pub settlement: WwmSettlementV1,
}

impl DevnetWwmFlowV1 {
    /// Validate cross-action identities and bounded terminal accounting before
    /// any transaction is submitted.
    pub fn validate(&self) -> Result<()> {
        let job = &self.job;
        let receipt = &self.receipt;
        let settlement = &self.settlement;
        if job.job_id == [0; 32]
            || job.chain_id == [0; 32]
            || job.genesis_hash == [0; 32]
            || job.capsule_id == [0; 32]
            || job.offchain_envelope_root == [0; 32]
        {
            return Err(CliError::Malformed(
                "WWM job carries a zero required identity".into(),
            ));
        }
        if receipt.receipt_id == [0; 32]
            || receipt.job_id != job.job_id
            || receipt.capsule_id != job.capsule_id
            || receipt.execution_profile_id != job.execution_profile_id
            || receipt.output_root == [0; 32]
            || receipt.token_history_root == [0; 32]
            || receipt.input_tokens > job.max_input_tokens
            || receipt.output_tokens > job.max_output_tokens
        {
            return Err(CliError::Malformed(
                "WWM receipt is not terminally bound to the exact job/capsule".into(),
            ));
        }
        if settlement.settlement_id == [0; 32]
            || settlement.job_id != job.job_id
            || settlement.receipt_id != receipt.receipt_id
            || settlement.fund_profile_id != job.fund_profile_id
            || settlement.bucket != noos_lumen::wwm::FundBucketTag::Job
            || settlement.paid_amount != receipt.paid_amount
            || settlement.refunded_amount != receipt.refunded_amount
        {
            return Err(CliError::Malformed(
                "WWM settlement is not bound to the exact job/receipt/fund route".into(),
            ));
        }
        let terminal_total = settlement
            .paid_amount
            .checked_add(settlement.refunded_amount)
            .and_then(|value| value.checked_add(settlement.released_amount))
            .ok_or_else(|| CliError::Malformed("WWM settlement amount overflow".into()))?;
        if terminal_total != job.reserved_amount {
            return Err(CliError::Malformed(
                "WWM settlement does not exhaust the reserved amount".into(),
            ));
        }
        Ok(())
    }

    /// Return the canonical OpenWwmJob → RecordWwmReceipt → SettleWwmJob
    /// action bytes after validating the complete flow.
    pub fn canonical_actions(&self) -> Result<[BoundedBytes<65536>; 3]> {
        self.validate()?;
        Ok([
            open_wwm_job(self.job.clone())?,
            record_wwm_receipt(self.receipt.clone())?,
            settle_wwm_job(self.settlement.clone())?,
        ])
    }
}

/// Append exactly one typed WWM action without changing any other transaction field.
pub fn append_wwm_action(mut tx: TransactionV1, action: ActionV1) -> Result<TransactionV1> {
    let mut actions = tx.actions.as_slice().to_vec();
    actions.push(encode_wwm_action(action)?);
    tx.actions = BoundedList::new(actions)
        .ok_or_else(|| CliError::Malformed("transaction exceeds 64 actions".into()))?;
    Ok(tx)
}

/// Validate the aggregate transaction plus segregated-witness carrier law.
pub fn validate_tx_witness_carrier(
    tx: &TransactionV1,
    witnesses: &TransactionWitnessesV1,
) -> Result<(usize, usize)> {
    let tx_len = tx.encode_canonical().len();
    let witness_len = witnesses.encode_canonical().len();
    if !carrier_len_valid(tx_len, witness_len) {
        return Err(CliError::Malformed(format!(
            "transaction plus witness is {} bytes; maximum is {MAX_TX_WITNESS_BYTES}",
            tx_len.saturating_add(witness_len)
        )));
    }
    Ok((tx_len, witness_len))
}

/// Build the exact TxPush inner carrier: `u32 tx_len || tx_bytes || witness_bytes`.
/// The returned vector is at most 65,536 bytes including the four-byte prefix.
pub fn build_tx_push_carrier(
    tx: &TransactionV1,
    witnesses: &TransactionWitnessesV1,
) -> Result<Vec<u8>> {
    let tx_bytes = tx.encode_canonical();
    let witness_bytes = witnesses.encode_canonical();
    if !carrier_len_valid(tx_bytes.len(), witness_bytes.len()) {
        return Err(CliError::Malformed(format!(
            "transaction plus witness is {} bytes; maximum is {MAX_TX_WITNESS_BYTES}",
            tx_bytes.len().saturating_add(witness_bytes.len())
        )));
    }
    let tx_len = u32::try_from(tx_bytes.len())
        .map_err(|_| CliError::Malformed("transaction length does not fit u32".into()))?;
    let capacity = 4usize
        .checked_add(tx_bytes.len())
        .and_then(|n| n.checked_add(witness_bytes.len()))
        .ok_or_else(|| CliError::Malformed("carrier length overflow".into()))?;
    let mut carrier = Vec::with_capacity(capacity);
    carrier.extend_from_slice(&tx_len.to_le_bytes());
    carrier.extend_from_slice(&tx_bytes);
    carrier.extend_from_slice(&witness_bytes);
    Ok(carrier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noos_codec::NoosDecode;
    use noos_lumen::objects::{OptionalObject, ResourceVector};
    use noos_lumen::wwm::{
        FundBucketTag, SignatureEntryV1, WwmEvidenceTier, WwmTerminalCode,
    };

    fn empty_tx() -> TransactionV1 {
        TransactionV1 {
            chain_id: [1; 32],
            format_version: 2,
            expiry_height: 1,
            fee_payer: [2; 32],
            fee_authorization: OptionalObject(None),
            resource_limits: ResourceVector::default(),
            note_inputs: BoundedList::default(),
            account_inputs: BoundedList::default(),
            object_access_list: BoundedList::default(),
            actions: BoundedList::default(),
            outputs: BoundedList::default(),
            evidence_refs: BoundedList::default(),
            witness_root: [0; 32],
        }
    }

    fn flow() -> DevnetWwmFlowV1 {
        let job = WwmJobV1 {
            job_id: [1; 32],
            chain_id: [2; 32],
            genesis_hash: [3; 32],
            quote_id: [4; 32],
            registry_epoch: 7,
            client_commitment: [5; 32],
            capsule_id: [6; 32],
            execution_profile_id: [7; 32],
            query_policy_id: [8; 32],
            max_input_tokens: 32,
            max_output_tokens: 16,
            deadline_height: 500,
            selected_executor_ids: BoundedList::new(vec![[9; 32]]).unwrap(),
            availability_certificate_id: [10; 32],
            fund_profile_id: [11; 32],
            reserved_amount: 100,
            offchain_envelope_root: [12; 32],
        };
        let receipt = WwmReceiptV1 {
            receipt_id: [13; 32],
            job_id: job.job_id,
            capsule_id: job.capsule_id,
            artifact_id: [14; 32],
            tokenizer_root: [15; 32],
            template_root: [16; 32],
            runtime_root: [17; 32],
            sbom_root: [18; 32],
            execution_profile_id: job.execution_profile_id,
            input_tokens: 4,
            output_tokens: 3,
            token_history_root: [19; 32],
            output_root: [20; 32],
            signer_ids: BoundedList::new(vec![[21; 32]]).unwrap(),
            control_cluster_ids: BoundedList::new(vec![[22; 32]]).unwrap(),
            evidence_tier: WwmEvidenceTier::LocalVerified,
            availability_until: 600,
            evidence_until: 600,
            anchor_height: 450,
            anchor_block: [23; 32],
            metered_amount: 30,
            paid_amount: 30,
            refunded_amount: 10,
            terminal_code: WwmTerminalCode::Complete,
            signatures: BoundedList::<SignatureEntryV1, 3>::default(),
        };
        let settlement = WwmSettlementV1 {
            settlement_id: [24; 32],
            job_id: job.job_id,
            receipt_id: receipt.receipt_id,
            fund_profile_id: job.fund_profile_id,
            bucket: FundBucketTag::Job,
            prior_settlement_index: 0,
            paid_amount: 30,
            refunded_amount: 10,
            released_amount: 60,
            settled_height: 451,
            authority_epoch: 1,
            signature: BoundedBytes::new(b"TESTNET_FIXTURE_ONLY".to_vec()).unwrap(),
        };
        DevnetWwmFlowV1 {
            job,
            receipt,
            settlement,
        }
    }

    #[test]
    fn devnet_operator_flow_encodes_open_receipt_settlement_in_order() {
        let flow = flow();
        let actions = flow.canonical_actions().unwrap();
        assert!(matches!(
            ActionV1::decode_canonical(actions[0].as_slice()).unwrap(),
            ActionV1::OpenWwmJob(_)
        ));
        assert!(matches!(
            ActionV1::decode_canonical(actions[1].as_slice()).unwrap(),
            ActionV1::RecordWwmReceipt(_)
        ));
        assert!(matches!(
            ActionV1::decode_canonical(actions[2].as_slice()).unwrap(),
            ActionV1::SettleWwmJob(_)
        ));
    }

    #[test]
    fn devnet_operator_flow_rejects_wrong_capsule_job_and_receipt_bindings() {
        let mut wrong_capsule = flow();
        wrong_capsule.receipt.capsule_id = [99; 32];
        assert!(wrong_capsule.canonical_actions().is_err());

        let mut wrong_job = flow();
        wrong_job.receipt.job_id = [98; 32];
        assert!(wrong_job.canonical_actions().is_err());

        let mut wrong_receipt = flow();
        wrong_receipt.settlement.receipt_id = [97; 32];
        assert!(wrong_receipt.canonical_actions().is_err());
    }

    #[test]
    fn carrier_prefix_and_edge_law_are_exact() {
        let tx = empty_tx();
        let witness = TransactionWitnessesV1 {
            intents: BoundedList::default(),
            lock_reveals: BoundedList::default(),
        };
        let carrier = build_tx_push_carrier(&tx, &witness).unwrap();
        let encoded = tx.encode_canonical();
        assert_eq!(&carrier[..4], &(encoded.len() as u32).to_le_bytes());
        assert_eq!(&carrier[4..4 + encoded.len()], encoded.as_slice());
        assert!(carrier.len() <= 65_536);
        assert!(carrier_len_valid(65_532, 0));
        assert!(!carrier_len_valid(65_533, 0));
    }
}
