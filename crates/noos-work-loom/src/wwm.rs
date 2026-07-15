//! Application-funded World Wide Mind capacity quotes and settlement.
//!
//! All accounting in this module is bounded by user or sponsor escrow. It has
//! no issuance, proposal-weight, finality-weight, Proofpower, or validator
//! reward hook. Role bonds remain non-slashable until an objective-fault gate
//! demonstrates zero false slashes.

use crate::Hash32;
use noos_codec::NoosEncode;
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use noos_lumen::{
    objects::{BoundedBytes, BoundedList, OptionalObject},
    wwm::{
        fund_route_key, genesis_fund_ledger, CoveragePolicyRowV1, FundBucketTag, FundLedgerRowV1,
        FundLedgerStatus, FundMutationLockRefV1, FundMutationLockStatus, FundMutationLockV1,
        FundMutationOperation, FundProfileV1, FundTopUpPermitV1, OptionalU64, WwmFundLedgerV1,
        FUND_BUCKET_COUNT,
    },
};
use std::collections::{BTreeMap, BTreeSet};

pub const BPS: u16 = 10_000;
pub const STEADY_MAX_DOMAIN_SHARE_BPS: u16 = 2_000;
pub const SURVIVOR_MAX_DOMAIN_SHARE_BPS: u16 = 2_500;
pub const STEADY_MIN_EXECUTOR_CLUSTERS: usize = 5;
pub const STEADY_MIN_STRUCTURAL_DOMAINS: usize = 5;
pub const SURVIVOR_MIN_EXECUTOR_CLUSTERS: usize = 4;
pub const SURVIVOR_MIN_REGIONS: usize = 4;
pub const WWM_APPLICATION_CREDIT_ENABLED: bool = false;
pub const WWM_OBJECTIVE_SLASHING_ENABLED: bool = false;
pub const WWM_PROOFPOWER_ENABLED: bool = false;
pub const WWM_DUPLEX_ISSUANCE_ENABLED: bool = false;
pub const WWM_BASE_ISSUANCE: u128 = 0;
pub const WWM_PROPOSAL_WEIGHT: u64 = 0;
pub const WWM_FINALITY_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WwmEconomicsError {
    InvalidFeeSchedule,
    InvalidQuote,
    InvalidSignature,
    DuplicateObject,
    UnknownQuote,
    QuoteExpired,
    BoundsExceeded,
    FeeCapExceeded,
    InvalidSettlementPolicy,
    InvalidSettlement,
    InvalidSponsorPolicy,
    SponsorCapExceeded,
    SponsorNotPrefunded,
    UnknownSponsorReservation,
    SponsorReservationAlreadyResolved,
    InvalidBond,
    UnknownBond,
    BondAlreadyResolved,
    BondStillLocked,
    InsufficientAccountBalance,
    InvalidPaymentIntent,
    PaymentIntentExpired,
    InvalidReceipt,
    ReceiptNotTerminal,
    SettlementAlreadyRecorded,
    InvalidFundProfile,
    InvalidFundLedger,
    InvalidFundPermit,
    InvalidFundLock,
    InvalidObligation,
    ObligationAlreadyConsumed,
    UnknownObligation,
    ReservationAdmissionFailed,
    InvalidConcentrationInput,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeUsage {
    pub prefill_tokens: u64,
    pub decode_tokens: u64,
    pub evidence_bytes: u64,
    pub verification_units: u64,
    pub route_bytes: u64,
    pub storage_bytes: u64,
    pub retention_epochs: u64,
}

impl FeeUsage {
    fn within(self, bounds: Self) -> bool {
        self.prefill_tokens <= bounds.prefill_tokens
            && self.decode_tokens <= bounds.decode_tokens
            && self.evidence_bytes <= bounds.evidence_bytes
            && self.verification_units <= bounds.verification_units
            && self.route_bytes <= bounds.route_bytes
            && self.storage_bytes <= bounds.storage_bytes
            && self.retention_epochs <= bounds.retention_epochs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSchedule {
    pub cold_load_fee: u128,
    pub resident_load_fee: u128,
    pub prefill_token_rate: u128,
    pub decode_token_rate: u128,
    pub evidence_byte_rate: u128,
    pub verification_unit_rate: u128,
    pub privacy_premium: u128,
    pub route_byte_rate: u128,
    pub storage_byte_epoch_rate: u128,
}

impl FeeSchedule {
    pub fn validate(self) -> Result<(), WwmEconomicsError> {
        if self.resident_load_fee > self.cold_load_fee
            || self.prefill_token_rate == 0
            || self.decode_token_rate == 0
        {
            return Err(WwmEconomicsError::InvalidFeeSchedule);
        }
        Ok(())
    }

    pub fn fee(
        self,
        usage: FeeUsage,
        residency: ResidencyCommitment,
    ) -> Result<u128, WwmEconomicsError> {
        self.validate()?;
        let load_fee = match residency {
            ResidencyCommitment::Resident => self.resident_load_fee,
            ResidencyCommitment::ColdStart => self.cold_load_fee,
        };
        let storage_byte_epochs = u128::from(usage.storage_bytes)
            .checked_mul(u128::from(usage.retention_epochs))
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let terms = [
            load_fee,
            multiply(self.prefill_token_rate, usage.prefill_tokens)?,
            multiply(self.decode_token_rate, usage.decode_tokens)?,
            multiply(self.evidence_byte_rate, usage.evidence_bytes)?,
            multiply(self.verification_unit_rate, usage.verification_units)?,
            self.privacy_premium,
            multiply(self.route_byte_rate, usage.route_bytes)?,
            self.storage_byte_epoch_rate
                .checked_mul(storage_byte_epochs)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?,
        ];
        checked_sum(terms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResidencyCommitment {
    Resident = 0,
    ColdStart = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteChainContext {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub execution_profile_id: Hash32,
    pub query_policy_id: Hash32,
    pub fee_policy_id: Hash32,
    pub fund_profile_id: Hash32,
    pub executor_registry_epoch: u64,
    pub fee_policy_epoch: u64,
    pub fund_profile_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityQuote {
    pub capsule_id: Hash32,
    pub numeric_profile_root: Hash32,
    pub chain_context: QuoteChainContext,
    pub provider_key: Hash32,
    pub provider_control_cluster: Hash32,
    pub cloud_account_root: Hash32,
    pub software_lineage_root: Hash32,
    pub model_publisher_root: Hash32,
    pub region_root: Hash32,
    pub asn: u32,
    pub residency: ResidencyCommitment,
    pub residency_commitment_root: Hash32,
    pub maximum_concurrent_jobs: u32,
    pub sustained_prefill_tokens_per_second: u64,
    pub sustained_decode_tokens_per_second: u64,
    pub fee_schedule: FeeSchedule,
    pub maximum_usage: FeeUsage,
    pub maximum_fee: u128,
    pub role_bond_id: Hash32,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub nonce: Hash32,
    pub quote_id: Hash32,
    pub signature: [u8; 64],
}

impl CapacityQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        capsule_id: Hash32,
        numeric_profile_root: Hash32,
        chain_context: QuoteChainContext,
        provider_control_cluster: Hash32,
        cloud_account_root: Hash32,
        software_lineage_root: Hash32,
        model_publisher_root: Hash32,
        region_root: Hash32,
        asn: u32,
        residency: ResidencyCommitment,
        residency_commitment_root: Hash32,
        maximum_concurrent_jobs: u32,
        sustained_prefill_tokens_per_second: u64,
        sustained_decode_tokens_per_second: u64,
        fee_schedule: FeeSchedule,
        maximum_usage: FeeUsage,
        role_bond_id: Hash32,
        valid_from_height: u64,
        expires_at_height: u64,
        nonce: Hash32,
        provider: &Keypair,
    ) -> Result<Self, WwmEconomicsError> {
        let maximum_fee = fee_schedule.fee(maximum_usage, residency)?;
        let mut value = Self {
            capsule_id,
            numeric_profile_root,
            chain_context,
            provider_key: provider.public_key().into_bytes(),
            provider_control_cluster,
            cloud_account_root,
            software_lineage_root,
            model_publisher_root,
            region_root,
            asn,
            residency,
            residency_commitment_root,
            maximum_concurrent_jobs,
            sustained_prefill_tokens_per_second,
            sustained_decode_tokens_per_second,
            fee_schedule,
            maximum_usage,
            maximum_fee,
            role_bond_id,
            valid_from_height,
            expires_at_height,
            nonce,
            quote_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body();
        value.quote_id = digest(DomainId::WwmCapacityQuote, &[&body])?;
        value.signature = sign(provider, DomainId::WwmCapacityQuote, value.quote_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), WwmEconomicsError> {
        self.validate_shape()?;
        let body = self.body();
        if digest(DomainId::WwmCapacityQuote, &[&body])? != self.quote_id {
            return Err(WwmEconomicsError::InvalidQuote);
        }
        verify(
            self.provider_key,
            DomainId::WwmCapacityQuote,
            self.quote_id,
            &body,
            self.signature,
        )
    }

    pub fn fee_for(&self, usage: FeeUsage) -> Result<u128, WwmEconomicsError> {
        if !usage.within(self.maximum_usage) {
            return Err(WwmEconomicsError::BoundsExceeded);
        }
        let fee = self.fee_schedule.fee(usage, self.residency)?;
        if fee > self.maximum_fee {
            return Err(WwmEconomicsError::FeeCapExceeded);
        }
        Ok(fee)
    }

    #[must_use]
    pub fn valid_at(&self, height: u64) -> bool {
        self.valid_from_height <= height && height < self.expires_at_height
    }

    fn validate_shape(&self) -> Result<(), WwmEconomicsError> {
        self.fee_schedule.validate()?;
        if [
            self.capsule_id,
            self.numeric_profile_root,
            self.chain_context.chain_id,
            self.chain_context.genesis_hash,
            self.chain_context.execution_profile_id,
            self.chain_context.query_policy_id,
            self.chain_context.fee_policy_id,
            self.chain_context.fund_profile_id,
            self.provider_key,
            self.provider_control_cluster,
            self.cloud_account_root,
            self.software_lineage_root,
            self.model_publisher_root,
            self.region_root,
            self.residency_commitment_root,
            self.role_bond_id,
            self.nonce,
        ]
        .contains(&[0; 32])
            || self.asn == 0
            || self.maximum_concurrent_jobs == 0
            || self.sustained_prefill_tokens_per_second == 0
            || self.sustained_decode_tokens_per_second == 0
            || self.valid_from_height >= self.expires_at_height
            || self.maximum_fee != self.fee_schedule.fee(self.maximum_usage, self.residency)?
        {
            return Err(WwmEconomicsError::InvalidQuote);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.capsule_id);
        out.extend(self.numeric_profile_root);
        out.extend(self.chain_context.chain_id);
        out.extend(self.chain_context.genesis_hash);
        out.extend(self.chain_context.execution_profile_id);
        out.extend(self.chain_context.query_policy_id);
        out.extend(self.chain_context.fee_policy_id);
        out.extend(self.chain_context.fund_profile_id);
        out.extend(self.chain_context.executor_registry_epoch.to_le_bytes());
        out.extend(self.chain_context.fee_policy_epoch.to_le_bytes());
        out.extend(self.chain_context.fund_profile_epoch.to_le_bytes());
        out.extend(self.provider_key);
        out.extend(self.provider_control_cluster);
        out.extend(self.cloud_account_root);
        out.extend(self.software_lineage_root);
        out.extend(self.model_publisher_root);
        out.extend(self.region_root);
        out.extend(self.asn.to_le_bytes());
        out.push(self.residency as u8);
        out.extend(self.residency_commitment_root);
        out.extend(self.maximum_concurrent_jobs.to_le_bytes());
        out.extend(self.sustained_prefill_tokens_per_second.to_le_bytes());
        out.extend(self.sustained_decode_tokens_per_second.to_le_bytes());
        encode_fee_schedule(&mut out, self.fee_schedule);
        encode_usage(&mut out, self.maximum_usage);
        out.extend(self.maximum_fee.to_le_bytes());
        out.extend(self.role_bond_id);
        out.extend(self.valid_from_height.to_le_bytes());
        out.extend(self.expires_at_height.to_le_bytes());
        out.extend(self.nonce);
        out
    }
}

#[derive(Debug, Default)]
pub struct CapacityMarket {
    quotes: BTreeMap<Hash32, CapacityQuote>,
}

impl CapacityMarket {
    pub fn register(&mut self, quote: CapacityQuote) -> Result<(), WwmEconomicsError> {
        quote.validate()?;
        if self.quotes.contains_key(&quote.quote_id) {
            return Err(WwmEconomicsError::DuplicateObject);
        }
        self.quotes.insert(quote.quote_id, quote);
        Ok(())
    }

    pub fn quote(
        &self,
        quote_id: &Hash32,
        height: u64,
    ) -> Result<&CapacityQuote, WwmEconomicsError> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or(WwmEconomicsError::UnknownQuote)?;
        if !quote.valid_at(height) {
            return Err(WwmEconomicsError::QuoteExpired);
        }
        Ok(quote)
    }

    #[must_use]
    pub fn eligible_quote_ids(
        &self,
        capsule_id: Hash32,
        height: u64,
        user_fee_cap: u128,
    ) -> Vec<Hash32> {
        self.quotes
            .iter()
            .filter_map(|(id, quote)| {
                (quote.capsule_id == capsule_id
                    && quote.valid_at(height)
                    && quote.maximum_fee <= user_fee_cap)
                    .then_some(*id)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementPolicy {
    pub executor_bps: u16,
    pub custodian_bps: u16,
    pub verifier_bps: u16,
    pub evaluator_bps: u16,
    pub relay_bps: u16,
    pub gateway_bps: u16,
    pub dispute_bounty_bps: u16,
    pub policy_root: Hash32,
}

impl SettlementPolicy {
    pub fn validate(self) -> Result<(), WwmEconomicsError> {
        let normal = [
            self.executor_bps,
            self.custodian_bps,
            self.verifier_bps,
            self.evaluator_bps,
            self.relay_bps,
            self.gateway_bps,
        ]
        .into_iter()
        .try_fold(0_u32, |total, value| total.checked_add(u32::from(value)))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let objective_failure = [
            self.verifier_bps,
            self.evaluator_bps,
            self.dispute_bounty_bps,
        ]
        .into_iter()
        .try_fold(0_u32, |total, value| total.checked_add(u32::from(value)))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        if normal > u32::from(BPS)
            || objective_failure > u32::from(BPS)
            || self.policy_root == [0; 32]
        {
            return Err(WwmEconomicsError::InvalidSettlementPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementAccounts {
    pub executor: Hash32,
    pub custodian: Hash32,
    pub verifier: Hash32,
    pub evaluator: Hash32,
    pub relay: Hash32,
    pub gateway: Hash32,
    pub challenger: Hash32,
    pub refund: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementVerdict {
    ValidDelivery,
    ObjectiveFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SettlementRole {
    Executor,
    Custodian,
    Verifier,
    Evaluator,
    Relay,
    Gateway,
    Challenger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolePayment {
    pub role: SettlementRole,
    pub account: Hash32,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSettlement {
    pub quote_id: Hash32,
    pub metered_fee: u128,
    pub escrowed_maximum: u128,
    pub payments: Vec<RolePayment>,
    pub refund_account: Hash32,
    pub refund_amount: u128,
    pub verdict: SettlementVerdict,
    pub issuance: u128,
    pub settlement_id: Hash32,
}

impl ApplicationSettlement {
    pub fn calculate(
        quote: &CapacityQuote,
        usage: FeeUsage,
        policy: SettlementPolicy,
        accounts: SettlementAccounts,
        verdict: SettlementVerdict,
        delivery_evidence_root: Hash32,
    ) -> Result<Self, WwmEconomicsError> {
        quote.validate()?;
        policy.validate()?;
        if [
            accounts.executor,
            accounts.custodian,
            accounts.verifier,
            accounts.evaluator,
            accounts.relay,
            accounts.gateway,
            accounts.challenger,
            accounts.refund,
            delivery_evidence_root,
        ]
        .contains(&[0; 32])
        {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        let metered_fee = quote.fee_for(usage)?;
        let mut payments = Vec::new();
        match verdict {
            SettlementVerdict::ValidDelivery => {
                push_payment(
                    &mut payments,
                    SettlementRole::Executor,
                    accounts.executor,
                    share(metered_fee, policy.executor_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Custodian,
                    accounts.custodian,
                    share(metered_fee, policy.custodian_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Verifier,
                    accounts.verifier,
                    share(metered_fee, policy.verifier_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Evaluator,
                    accounts.evaluator,
                    share(metered_fee, policy.evaluator_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Relay,
                    accounts.relay,
                    share(metered_fee, policy.relay_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Gateway,
                    accounts.gateway,
                    share(metered_fee, policy.gateway_bps)?,
                )?;
            }
            SettlementVerdict::ObjectiveFailure => {
                // Evaluators and verifiers are paid for committed evidence even
                // when the executor result is unfavorable. The bounded bounty
                // comes from application escrow, never issuance or bond slash.
                push_payment(
                    &mut payments,
                    SettlementRole::Verifier,
                    accounts.verifier,
                    share(metered_fee, policy.verifier_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Evaluator,
                    accounts.evaluator,
                    share(metered_fee, policy.evaluator_bps)?,
                )?;
                push_payment(
                    &mut payments,
                    SettlementRole::Challenger,
                    accounts.challenger,
                    share(metered_fee, policy.dispute_bounty_bps)?,
                )?;
            }
        }
        payments.sort_unstable_by_key(|payment| payment.role);
        let paid = checked_sum(payments.iter().map(|payment| payment.amount))?;
        let refund_amount = quote
            .maximum_fee
            .checked_sub(paid)
            .ok_or(WwmEconomicsError::InvalidSettlement)?;
        let value = Self {
            quote_id: quote.quote_id,
            metered_fee,
            escrowed_maximum: quote.maximum_fee,
            payments,
            refund_account: accounts.refund,
            refund_amount,
            verdict,
            issuance: 0,
            settlement_id: [0; 32],
        };
        let mut value = value;
        value.settlement_id = digest(DomainId::WwmPublicReceipt, &[b"SETTLEMENT", &value.body()?])?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), WwmEconomicsError> {
        if self.quote_id == [0; 32]
            || self.refund_account == [0; 32]
            || self.settlement_id == [0; 32]
            || self.metered_fee > self.escrowed_maximum
            || self.issuance != 0
            || !strictly_sorted_by(&self.payments, |payment| payment.role)
        {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        let paid = checked_sum(self.payments.iter().map(|payment| payment.amount))?;
        if paid
            .checked_add(self.refund_amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?
            != self.escrowed_maximum
            || digest(DomainId::WwmPublicReceipt, &[b"SETTLEMENT", &self.body()?])?
                != self.settlement_id
        {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, WwmEconomicsError> {
        let mut out = Vec::new();
        out.extend(self.quote_id);
        out.extend(self.metered_fee.to_le_bytes());
        out.extend(self.escrowed_maximum.to_le_bytes());
        out.extend(
            u16::try_from(self.payments.len())
                .map_err(|_| WwmEconomicsError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for payment in &self.payments {
            out.push(payment.role as u8);
            out.extend(payment.account);
            out.extend(payment.amount.to_le_bytes());
        }
        out.extend(self.refund_account);
        out.extend(self.refund_amount.to_le_bytes());
        out.push(match self.verdict {
            SettlementVerdict::ValidDelivery => 0,
            SettlementVerdict::ObjectiveFailure => 1,
        });
        out.extend(self.issuance.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestedEvidenceTier {
    SignedSingle = 0,
    MatchedQuorum = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorClaim {
    pub signer_id: Hash32,
    pub control_cluster_id: Hash32,
    pub ordered_token_ids_root: Hash32,
    pub token_history_root: Hash32,
    pub output_root: Hash32,
}

impl ExecutorClaim {
    fn validate(self) -> Result<(), WwmEconomicsError> {
        if [
            self.signer_id,
            self.control_cluster_id,
            self.ordered_token_ids_root,
            self.token_history_root,
            self.output_root,
        ]
        .contains(&[0; 32])
        {
            return Err(WwmEconomicsError::InvalidReceipt);
        }
        Ok(())
    }

    fn matches_output(self, other: Self) -> bool {
        self.ordered_token_ids_root == other.ordered_token_ids_root
            && self.token_history_root == other.token_history_root
            && self.output_root == other.output_root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptTerminalCode {
    Success,
    NoQuorum,
    Cancelled,
    DeadlineExceeded,
    ObjectiveFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptOutcome {
    pub terminal_code: ReceiptTerminalCode,
    pub evidence_tier: RequestedEvidenceTier,
    pub matching_backup: Option<Hash32>,
    pub minority_disagreement: Option<Hash32>,
}

impl ReceiptOutcome {
    pub fn evaluate(
        requested: RequestedEvidenceTier,
        primary: ExecutorClaim,
        backups: &[ExecutorClaim],
        deadline_reached: bool,
    ) -> Result<Self, WwmEconomicsError> {
        primary.validate()?;
        if backups.len() > 2
            || !strictly_sorted_by(backups, |claim| claim.signer_id)
            || backups.iter().any(|claim| claim.validate().is_err())
            || backups.iter().any(|claim| {
                claim.signer_id == primary.signer_id
                    || claim.control_cluster_id == primary.control_cluster_id
            })
            || backups
                .iter()
                .map(|claim| claim.control_cluster_id)
                .collect::<BTreeSet<_>>()
                .len()
                != backups.len()
        {
            return Err(WwmEconomicsError::InvalidReceipt);
        }
        match requested {
            RequestedEvidenceTier::SignedSingle => {
                if !backups.is_empty() {
                    return Err(WwmEconomicsError::InvalidReceipt);
                }
                Ok(Self {
                    terminal_code: ReceiptTerminalCode::Success,
                    evidence_tier: RequestedEvidenceTier::SignedSingle,
                    matching_backup: None,
                    minority_disagreement: None,
                })
            }
            RequestedEvidenceTier::MatchedQuorum => {
                if backups.len() != 2 {
                    return Err(WwmEconomicsError::InvalidReceipt);
                }
                let matching = backups
                    .iter()
                    .find(|claim| primary.matches_output(**claim))
                    .copied();
                if let Some(matching) = matching {
                    let minority_disagreement = backups
                        .iter()
                        .find(|claim| claim.signer_id != matching.signer_id)
                        .filter(|claim| !primary.matches_output(**claim))
                        .map(|claim| claim.signer_id);
                    return Ok(Self {
                        terminal_code: ReceiptTerminalCode::Success,
                        evidence_tier: RequestedEvidenceTier::MatchedQuorum,
                        matching_backup: Some(matching.signer_id),
                        minority_disagreement,
                    });
                }
                if !deadline_reached {
                    return Err(WwmEconomicsError::ReceiptNotTerminal);
                }
                Ok(Self {
                    terminal_code: ReceiptTerminalCode::NoQuorum,
                    evidence_tier: RequestedEvidenceTier::MatchedQuorum,
                    matching_backup: None,
                    minority_disagreement: None,
                })
            }
        }
    }

    #[must_use]
    pub const fn refundable(self) -> bool {
        matches!(
            self.terminal_code,
            ReceiptTerminalCode::NoQuorum
                | ReceiptTerminalCode::Cancelled
                | ReceiptTerminalCode::DeadlineExceeded
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSettlement {
    pub job_id: Hash32,
    pub terminal_code: ReceiptTerminalCode,
    pub application: Option<ApplicationSettlement>,
    pub paid: u128,
    pub refund: u128,
}

#[derive(Debug, Default)]
pub struct SettlementBook {
    settlements: BTreeMap<Hash32, TerminalSettlement>,
}

impl SettlementBook {
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        job_id: Hash32,
        outcome: ReceiptOutcome,
        quote: &CapacityQuote,
        usage: FeeUsage,
        policy: SettlementPolicy,
        accounts: SettlementAccounts,
        delivery_evidence_root: Hash32,
    ) -> Result<&TerminalSettlement, WwmEconomicsError> {
        if job_id == [0; 32] {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        if self.settlements.contains_key(&job_id) {
            return Err(WwmEconomicsError::SettlementAlreadyRecorded);
        }
        let application = match outcome.terminal_code {
            ReceiptTerminalCode::Success => Some(ApplicationSettlement::calculate(
                quote,
                usage,
                policy,
                accounts,
                SettlementVerdict::ValidDelivery,
                delivery_evidence_root,
            )?),
            ReceiptTerminalCode::ObjectiveFailure => Some(ApplicationSettlement::calculate(
                quote,
                usage,
                policy,
                accounts,
                SettlementVerdict::ObjectiveFailure,
                delivery_evidence_root,
            )?),
            ReceiptTerminalCode::NoQuorum
            | ReceiptTerminalCode::Cancelled
            | ReceiptTerminalCode::DeadlineExceeded => None,
        };
        let paid = application
            .as_ref()
            .map(|settlement| {
                settlement
                    .escrowed_maximum
                    .checked_sub(settlement.refund_amount)
                    .ok_or(WwmEconomicsError::InvalidSettlement)
            })
            .transpose()?
            .unwrap_or(0);
        let refund = quote
            .maximum_fee
            .checked_sub(paid)
            .ok_or(WwmEconomicsError::InvalidSettlement)?;
        if paid
            .checked_add(refund)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?
            != quote.maximum_fee
        {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        self.settlements.insert(
            job_id,
            TerminalSettlement {
                job_id,
                terminal_code: outcome.terminal_code,
                application,
                paid,
                refund,
            },
        );
        self.settlements
            .get(&job_id)
            .ok_or(WwmEconomicsError::InvalidSettlement)
    }

    #[must_use]
    pub fn get(&self, job_id: &Hash32) -> Option<&TerminalSettlement> {
        self.settlements.get(job_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FundingClassification {
    IndependentlyFunded,
    SelfDealing,
    CircularFunding,
    UnresolvedControl,
}

impl FundingClassification {
    #[must_use]
    pub const fn eligible_for_production_credit_if_gate_passed(self) -> bool {
        matches!(self, Self::IndependentlyFunded)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorPolicy {
    pub sponsor_id: Hash32,
    pub sponsor_control_cluster: Hash32,
    pub maximum_fee_per_job: u128,
    pub maximum_daily_spend: u128,
    pub maximum_daily_jobs: u32,
    pub maximum_total_spend: u128,
    pub policy_root: Hash32,
}

impl SponsorPolicy {
    fn validate(self) -> Result<(), WwmEconomicsError> {
        if [
            self.sponsor_id,
            self.sponsor_control_cluster,
            self.policy_root,
        ]
        .contains(&[0; 32])
            || self.maximum_fee_per_job == 0
            || self.maximum_daily_spend < self.maximum_fee_per_job
            || self.maximum_daily_jobs == 0
            || self.maximum_total_spend < self.maximum_daily_spend
        {
            return Err(WwmEconomicsError::InvalidSponsorPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorReservation {
    pub job_id: Hash32,
    pub sponsor_id: Hash32,
    pub amount: u128,
    pub day: u64,
    pub funding_classification: FundingClassification,
    pub control_evidence_root: Hash32,
    pub production_credit: u128,
    pub reservation_id: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorResolution {
    pub reservation_id: Hash32,
    pub spent: u128,
    pub released: u128,
}

#[derive(Debug, Default)]
pub struct SponsorBook {
    reservations: BTreeMap<Hash32, SponsorReservation>,
    resolved: BTreeSet<Hash32>,
    available: BTreeMap<Hash32, u128>,
    reserved: BTreeMap<Hash32, u128>,
    daily_usage: BTreeMap<(Hash32, u64), (u128, u32)>,
    total_usage: BTreeMap<Hash32, u128>,
}

impl SponsorBook {
    pub fn prefund(
        &mut self,
        policy: SponsorPolicy,
        amount: u128,
    ) -> Result<(), WwmEconomicsError> {
        policy.validate()?;
        if amount == 0 {
            return Err(WwmEconomicsError::SponsorNotPrefunded);
        }
        let next = self
            .available
            .get(&policy.sponsor_id)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        if next > policy.maximum_total_spend {
            return Err(WwmEconomicsError::SponsorCapExceeded);
        }
        self.available.insert(policy.sponsor_id, next);
        Ok(())
    }

    pub fn reserve(
        &mut self,
        policy: SponsorPolicy,
        job_id: Hash32,
        amount: u128,
        day: u64,
        funding_classification: FundingClassification,
        control_evidence_root: Hash32,
    ) -> Result<SponsorReservation, WwmEconomicsError> {
        policy.validate()?;
        if job_id == [0; 32]
            || control_evidence_root == [0; 32]
            || amount == 0
            || amount > policy.maximum_fee_per_job
        {
            return Err(WwmEconomicsError::SponsorCapExceeded);
        }
        if self.reservations.contains_key(&job_id) {
            return Err(WwmEconomicsError::DuplicateObject);
        }
        let available = self.available.get(&policy.sponsor_id).copied().unwrap_or(0);
        if available < amount {
            return Err(WwmEconomicsError::SponsorNotPrefunded);
        }
        let (daily_spend, daily_jobs) = self
            .daily_usage
            .get(&(policy.sponsor_id, day))
            .copied()
            .unwrap_or((0, 0));
        let next_daily_spend = daily_spend
            .checked_add(amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let next_daily_jobs = daily_jobs
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let total = self
            .total_usage
            .get(&policy.sponsor_id)
            .copied()
            .unwrap_or(0);
        let next_total = total
            .checked_add(amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        if next_daily_spend > policy.maximum_daily_spend
            || next_daily_jobs > policy.maximum_daily_jobs
            || next_total > policy.maximum_total_spend
        {
            return Err(WwmEconomicsError::SponsorCapExceeded);
        }
        let production_credit = if WWM_APPLICATION_CREDIT_ENABLED
            && funding_classification.eligible_for_production_credit_if_gate_passed()
        {
            amount
        } else {
            0
        };
        let reservation_id = digest(
            DomainId::WwmCapacityQuote,
            &[
                b"SPONSOR",
                &job_id,
                &policy.sponsor_id,
                &amount.to_le_bytes(),
                &day.to_le_bytes(),
                &[funding_classification as u8],
                &control_evidence_root,
            ],
        )?;
        let reservation = SponsorReservation {
            job_id,
            sponsor_id: policy.sponsor_id,
            amount,
            day,
            funding_classification,
            control_evidence_root,
            production_credit,
            reservation_id,
        };
        self.available.insert(policy.sponsor_id, available - amount);
        let reserved = self
            .reserved
            .get(&policy.sponsor_id)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        self.reserved.insert(policy.sponsor_id, reserved);
        self.daily_usage.insert(
            (policy.sponsor_id, day),
            (next_daily_spend, next_daily_jobs),
        );
        self.total_usage.insert(policy.sponsor_id, next_total);
        self.reservations.insert(job_id, reservation);
        Ok(reservation)
    }

    pub fn resolve(
        &mut self,
        job_id: Hash32,
        spent: u128,
    ) -> Result<SponsorResolution, WwmEconomicsError> {
        let reservation = self
            .reservations
            .get(&job_id)
            .copied()
            .ok_or(WwmEconomicsError::UnknownSponsorReservation)?;
        if spent > reservation.amount {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        if self.resolved.contains(&job_id) {
            return Err(WwmEconomicsError::SponsorReservationAlreadyResolved);
        }
        let held = self
            .reserved
            .get(&reservation.sponsor_id)
            .copied()
            .unwrap_or(0);
        let next_held = held
            .checked_sub(reservation.amount)
            .ok_or(WwmEconomicsError::InvalidSettlement)?;
        let released = reservation
            .amount
            .checked_sub(spent)
            .ok_or(WwmEconomicsError::InvalidSettlement)?;
        let available = self
            .available
            .get(&reservation.sponsor_id)
            .copied()
            .unwrap_or(0)
            .checked_add(released)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        self.resolved.insert(job_id);
        self.reserved.insert(reservation.sponsor_id, next_held);
        self.available.insert(reservation.sponsor_id, available);
        Ok(SponsorResolution {
            reservation_id: reservation.reservation_id,
            spent,
            released,
        })
    }

    #[must_use]
    pub fn balances(&self, sponsor_id: Hash32) -> (u128, u128) {
        (
            self.available.get(&sponsor_id).copied().unwrap_or(0),
            self.reserved.get(&sponsor_id).copied().unwrap_or(0),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondRole {
    Executor = 0,
    Custodian = 1,
    Verifier = 2,
    Evaluator = 3,
    Relay = 4,
    Gateway = 5,
    Challenger = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBond {
    pub role: BondRole,
    pub account_key: Hash32,
    pub control_cluster: Hash32,
    pub amount: u128,
    pub exposure_ceiling: u128,
    pub maximum_dispute_cost_reserve: u128,
    pub policy_root: Hash32,
    pub locked_until_height: u64,
    pub nonce: Hash32,
    pub bond_id: Hash32,
    pub signature: [u8; 64],
}

impl RoleBond {
    #[allow(clippy::too_many_arguments)]
    pub fn lock(
        role: BondRole,
        control_cluster: Hash32,
        amount: u128,
        exposure_ceiling: u128,
        maximum_dispute_cost_reserve: u128,
        policy_root: Hash32,
        locked_until_height: u64,
        nonce: Hash32,
        account: &Keypair,
    ) -> Result<Self, WwmEconomicsError> {
        let mut value = Self {
            role,
            account_key: account.public_key().into_bytes(),
            control_cluster,
            amount,
            exposure_ceiling,
            maximum_dispute_cost_reserve,
            policy_root,
            locked_until_height,
            nonce,
            bond_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body();
        value.bond_id = digest(DomainId::WwmCapacityQuote, &[b"ROLE-BOND", &body])?;
        value.signature = sign(account, DomainId::WwmCapacityQuote, value.bond_id, &body)?;
        Ok(value)
    }

    pub fn minimum_post_gate_amount(&self) -> Result<u128, WwmEconomicsError> {
        self.exposure_ceiling
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.maximum_dispute_cost_reserve))
            .ok_or(WwmEconomicsError::ArithmeticOverflow)
    }

    pub fn validate(&self) -> Result<(), WwmEconomicsError> {
        self.validate_shape()?;
        let body = self.body();
        if digest(DomainId::WwmCapacityQuote, &[b"ROLE-BOND", &body])? != self.bond_id {
            return Err(WwmEconomicsError::InvalidBond);
        }
        verify(
            self.account_key,
            DomainId::WwmCapacityQuote,
            self.bond_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), WwmEconomicsError> {
        if [
            self.account_key,
            self.control_cluster,
            self.policy_root,
            self.nonce,
        ]
        .contains(&[0; 32])
            || self.amount == 0
            || self.exposure_ceiling == 0
            || self.locked_until_height == 0
        {
            return Err(WwmEconomicsError::InvalidBond);
        }
        if WWM_OBJECTIVE_SLASHING_ENABLED && self.amount < self.minimum_post_gate_amount()? {
            return Err(WwmEconomicsError::InvalidBond);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.role as u8);
        out.extend(self.account_key);
        out.extend(self.control_cluster);
        out.extend(self.amount.to_le_bytes());
        out.extend(self.exposure_ceiling.to_le_bytes());
        out.extend(self.maximum_dispute_cost_reserve.to_le_bytes());
        out.extend(self.policy_root);
        out.extend(self.locked_until_height.to_le_bytes());
        out.extend(self.nonce);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondFinding {
    NoObjectiveFault,
    ObjectiveFault,
    SubjectiveOrUnattributable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondResolution {
    pub bond_id: Hash32,
    pub finding: BondFinding,
    pub returned_amount: u128,
    pub slashed_amount: u128,
    pub exclude_from_selection: bool,
}

#[derive(Debug, Default)]
pub struct BondLedger {
    bonds: BTreeMap<Hash32, RoleBond>,
    resolved: BTreeSet<Hash32>,
    account_balances: BTreeMap<Hash32, u128>,
    held_total: u128,
}

impl BondLedger {
    pub fn credit_account(
        &mut self,
        account: Hash32,
        amount: u128,
    ) -> Result<(), WwmEconomicsError> {
        if account == [0; 32] || amount == 0 {
            return Err(WwmEconomicsError::InvalidBond);
        }
        let next = self
            .account_balances
            .get(&account)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        self.account_balances.insert(account, next);
        Ok(())
    }

    pub fn register(&mut self, bond: RoleBond) -> Result<(), WwmEconomicsError> {
        bond.validate()?;
        if self.bonds.contains_key(&bond.bond_id) {
            return Err(WwmEconomicsError::DuplicateObject);
        }
        let balance = self
            .account_balances
            .get(&bond.account_key)
            .copied()
            .unwrap_or(0);
        let next_balance = balance
            .checked_sub(bond.amount)
            .ok_or(WwmEconomicsError::InsufficientAccountBalance)?;
        let next_held = self
            .held_total
            .checked_add(bond.amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        self.account_balances.insert(bond.account_key, next_balance);
        self.held_total = next_held;
        self.bonds.insert(bond.bond_id, bond);
        Ok(())
    }

    pub fn resolve(
        &mut self,
        bond_id: Hash32,
        finding: BondFinding,
        current_height: u64,
    ) -> Result<BondResolution, WwmEconomicsError> {
        let bond = self
            .bonds
            .get(&bond_id)
            .ok_or(WwmEconomicsError::UnknownBond)?;
        if current_height < bond.locked_until_height {
            return Err(WwmEconomicsError::BondStillLocked);
        }
        if self.resolved.contains(&bond_id) {
            return Err(WwmEconomicsError::BondAlreadyResolved);
        }
        let returned_amount = bond.amount;
        let slashed_amount = 0;
        let balance = self
            .account_balances
            .get(&bond.account_key)
            .copied()
            .unwrap_or(0);
        let next_balance = balance
            .checked_add(returned_amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let next_held = self
            .held_total
            .checked_sub(returned_amount)
            .ok_or(WwmEconomicsError::InvalidBond)?;
        self.resolved.insert(bond_id);
        self.account_balances.insert(bond.account_key, next_balance);
        self.held_total = next_held;
        Ok(BondResolution {
            bond_id,
            finding,
            returned_amount,
            slashed_amount,
            exclude_from_selection: finding == BondFinding::ObjectiveFault,
        })
    }

    #[must_use]
    pub fn account_balance(&self, account: Hash32) -> u128 {
        self.account_balances.get(&account).copied().unwrap_or(0)
    }

    #[must_use]
    pub const fn held_total(&self) -> u128 {
        self.held_total
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivatePaymentIntent {
    pub job_id: Hash32,
    pub quote_id: Hash32,
    pub one_time_payment_key: Hash32,
    pub payer_commitment: Hash32,
    pub refund_commitment: Hash32,
    pub payment_nullifier: Hash32,
    pub encrypted_memo_root: Hash32,
    pub route_policy_root: Hash32,
    pub maximum_amount: u128,
    pub expires_at_height: u64,
    pub intent_id: Hash32,
    pub signature: [u8; 64],
}

impl PrivatePaymentIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        job_id: Hash32,
        quote_id: Hash32,
        payer_commitment: Hash32,
        refund_commitment: Hash32,
        payment_nullifier: Hash32,
        encrypted_memo_root: Hash32,
        route_policy_root: Hash32,
        maximum_amount: u128,
        expires_at_height: u64,
        one_time_payment_key: &Keypair,
    ) -> Result<Self, WwmEconomicsError> {
        let mut value = Self {
            job_id,
            quote_id,
            one_time_payment_key: one_time_payment_key.public_key().into_bytes(),
            payer_commitment,
            refund_commitment,
            payment_nullifier,
            encrypted_memo_root,
            route_policy_root,
            maximum_amount,
            expires_at_height,
            intent_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body();
        value.intent_id = digest(DomainId::WwmCapacityQuote, &[b"PRIVATE-PAYMENT", &body])?;
        value.signature = sign(
            one_time_payment_key,
            DomainId::WwmCapacityQuote,
            value.intent_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self, height: u64) -> Result<(), WwmEconomicsError> {
        self.validate_shape()?;
        if height >= self.expires_at_height {
            return Err(WwmEconomicsError::PaymentIntentExpired);
        }
        let body = self.body();
        if digest(DomainId::WwmCapacityQuote, &[b"PRIVATE-PAYMENT", &body])? != self.intent_id {
            return Err(WwmEconomicsError::InvalidPaymentIntent);
        }
        verify(
            self.one_time_payment_key,
            DomainId::WwmCapacityQuote,
            self.intent_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), WwmEconomicsError> {
        if [
            self.job_id,
            self.quote_id,
            self.one_time_payment_key,
            self.payer_commitment,
            self.refund_commitment,
            self.payment_nullifier,
            self.encrypted_memo_root,
            self.route_policy_root,
        ]
        .contains(&[0; 32])
            || self.maximum_amount == 0
            || self.expires_at_height == 0
        {
            return Err(WwmEconomicsError::InvalidPaymentIntent);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.job_id);
        out.extend(self.quote_id);
        out.extend(self.one_time_payment_key);
        out.extend(self.payer_commitment);
        out.extend(self.refund_commitment);
        out.extend(self.payment_nullifier);
        out.extend(self.encrypted_memo_root);
        out.extend(self.route_policy_root);
        out.extend(self.maximum_amount.to_le_bytes());
        out.extend(self.expires_at_height.to_le_bytes());
        out
    }
}

#[derive(Debug, Default)]
pub struct PaymentIntentRegistry {
    intents: BTreeMap<Hash32, PrivatePaymentIntent>,
    nullifiers: BTreeSet<Hash32>,
}

impl PaymentIntentRegistry {
    pub fn register(
        &mut self,
        intent: PrivatePaymentIntent,
        height: u64,
    ) -> Result<(), WwmEconomicsError> {
        intent.validate(height)?;
        if self.intents.contains_key(&intent.intent_id)
            || !self.nullifiers.insert(intent.payment_nullifier)
        {
            return Err(WwmEconomicsError::DuplicateObject);
        }
        self.intents.insert(intent.intent_id, intent);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FailureDomainKind {
    ControlCluster = 0,
    CloudAccount = 1,
    Asn = 2,
    Region = 3,
    SoftwareLineage = 4,
    ModelPublisher = 5,
    BeneficialOwner = 6,
    InfrastructureProvider = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityAllocation {
    pub quote_id: Hash32,
    pub control_cluster: Hash32,
    pub cloud_account: Hash32,
    pub asn_root: Hash32,
    pub region: Hash32,
    pub software_lineage: Hash32,
    pub model_publisher: Hash32,
    pub beneficial_owner: Hash32,
    pub infrastructure_provider: Hash32,
    pub selection_weight: u128,
    pub custody_bytes: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcentrationPeak {
    pub kind: FailureDomainKind,
    pub selection_domain_id: Hash32,
    pub selection_share_bps: u16,
    pub custody_domain_id: Hash32,
    pub custody_share_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcentrationReport {
    pub allocation_root: Hash32,
    pub independent_control_clusters: usize,
    pub independent_regions: usize,
    pub independent_beneficial_owners: usize,
    pub independent_asns: usize,
    pub independent_providers: usize,
    pub peaks: Vec<ConcentrationPeak>,
    pub steady_gate_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurvivorConcentrationReport {
    pub lost_kind: FailureDomainKind,
    pub lost_domain_id: Hash32,
    pub surviving: ConcentrationReport,
    pub survivor_gate_passed: bool,
}

impl ConcentrationReport {
    pub fn build(allocations: &[CapacityAllocation]) -> Result<Self, WwmEconomicsError> {
        if allocations.is_empty()
            || !strictly_sorted_by(allocations, |allocation| allocation.quote_id)
            || allocations.iter().any(|allocation| {
                [
                    allocation.quote_id,
                    allocation.control_cluster,
                    allocation.cloud_account,
                    allocation.asn_root,
                    allocation.region,
                    allocation.software_lineage,
                    allocation.model_publisher,
                    allocation.beneficial_owner,
                    allocation.infrastructure_provider,
                ]
                .contains(&[0; 32])
                    || allocation.selection_weight == 0
                    || allocation.custody_bytes == 0
            })
        {
            return Err(WwmEconomicsError::InvalidConcentrationInput);
        }
        let total_selection = checked_sum(allocations.iter().map(|value| value.selection_weight))?;
        let total_custody = checked_sum(allocations.iter().map(|value| value.custody_bytes))?;
        let mut peaks = Vec::new();
        for kind in [
            FailureDomainKind::ControlCluster,
            FailureDomainKind::CloudAccount,
            FailureDomainKind::Asn,
            FailureDomainKind::Region,
            FailureDomainKind::SoftwareLineage,
            FailureDomainKind::ModelPublisher,
            FailureDomainKind::BeneficialOwner,
            FailureDomainKind::InfrastructureProvider,
        ] {
            let mut grouped = BTreeMap::<Hash32, (u128, u128)>::new();
            for allocation in allocations {
                let id = failure_domain_id(*allocation, kind);
                let prior = grouped.get(&id).copied().unwrap_or((0, 0));
                grouped.insert(
                    id,
                    (
                        prior
                            .0
                            .checked_add(allocation.selection_weight)
                            .ok_or(WwmEconomicsError::ArithmeticOverflow)?,
                        prior
                            .1
                            .checked_add(allocation.custody_bytes)
                            .ok_or(WwmEconomicsError::ArithmeticOverflow)?,
                    ),
                );
            }
            let (selection_domain_id, selection) = grouped
                .iter()
                .map(|(id, (selection, _))| (*id, *selection))
                .max_by_key(|(_, value)| *value)
                .ok_or(WwmEconomicsError::InvalidConcentrationInput)?;
            let (custody_domain_id, custody) = grouped
                .iter()
                .map(|(id, (_, custody))| (*id, *custody))
                .max_by_key(|(_, value)| *value)
                .ok_or(WwmEconomicsError::InvalidConcentrationInput)?;
            peaks.push(ConcentrationPeak {
                kind,
                selection_domain_id,
                selection_share_bps: share_bps_ceil(selection, total_selection)?,
                custody_domain_id,
                custody_share_bps: share_bps_ceil(custody, total_custody)?,
            });
        }
        let clusters = unique_domains(allocations, FailureDomainKind::ControlCluster);
        let regions = unique_domains(allocations, FailureDomainKind::Region);
        let owners = unique_domains(allocations, FailureDomainKind::BeneficialOwner);
        let asns = unique_domains(allocations, FailureDomainKind::Asn);
        let providers = unique_domains(allocations, FailureDomainKind::InfrastructureProvider);
        let steady_gate_passed = clusters >= STEADY_MIN_EXECUTOR_CLUSTERS
            && regions >= STEADY_MIN_STRUCTURAL_DOMAINS
            && owners >= STEADY_MIN_STRUCTURAL_DOMAINS
            && asns >= STEADY_MIN_STRUCTURAL_DOMAINS
            && providers >= STEADY_MIN_STRUCTURAL_DOMAINS
            && peaks.iter().all(|peak| {
                peak.selection_share_bps <= STEADY_MAX_DOMAIN_SHARE_BPS
                    && peak.custody_share_bps <= SURVIVOR_MAX_DOMAIN_SHARE_BPS
            });
        let mut encoded = Vec::new();
        for allocation in allocations {
            encoded.extend(allocation.quote_id);
            encoded.extend(allocation.control_cluster);
            encoded.extend(allocation.cloud_account);
            encoded.extend(allocation.asn_root);
            encoded.extend(allocation.region);
            encoded.extend(allocation.software_lineage);
            encoded.extend(allocation.model_publisher);
            encoded.extend(allocation.beneficial_owner);
            encoded.extend(allocation.infrastructure_provider);
            encoded.extend(allocation.selection_weight.to_le_bytes());
            encoded.extend(allocation.custody_bytes.to_le_bytes());
        }
        Ok(Self {
            allocation_root: digest(DomainId::WwmCapacityQuote, &[b"CONCENTRATION", &encoded])?,
            independent_control_clusters: clusters,
            independent_regions: regions,
            independent_beneficial_owners: owners,
            independent_asns: asns,
            independent_providers: providers,
            peaks,
            steady_gate_passed,
        })
    }

    pub fn after_largest_domain_loss(
        allocations: &[CapacityAllocation],
        lost_kind: FailureDomainKind,
    ) -> Result<SurvivorConcentrationReport, WwmEconomicsError> {
        if !matches!(
            lost_kind,
            FailureDomainKind::ControlCluster
                | FailureDomainKind::Region
                | FailureDomainKind::InfrastructureProvider
        ) {
            return Err(WwmEconomicsError::InvalidConcentrationInput);
        }
        let mut grouped = BTreeMap::<Hash32, u128>::new();
        for allocation in allocations {
            let domain = failure_domain_id(*allocation, lost_kind);
            let next = grouped
                .get(&domain)
                .copied()
                .unwrap_or(0)
                .checked_add(allocation.selection_weight)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
            grouped.insert(domain, next);
        }
        let lost_domain_id = grouped
            .into_iter()
            .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
            .map(|(domain, _)| domain)
            .ok_or(WwmEconomicsError::InvalidConcentrationInput)?;
        let surviving_allocations = allocations
            .iter()
            .copied()
            .filter(|allocation| failure_domain_id(*allocation, lost_kind) != lost_domain_id)
            .collect::<Vec<_>>();
        let surviving = Self::build(&surviving_allocations)?;
        let survivor_gate_passed = surviving.independent_control_clusters
            >= SURVIVOR_MIN_EXECUTOR_CLUSTERS
            && surviving.independent_regions >= SURVIVOR_MIN_REGIONS
            && surviving
                .peaks
                .iter()
                .all(|peak| peak.selection_share_bps <= SURVIVOR_MAX_DOMAIN_SHARE_BPS);
        Ok(SurvivorConcentrationReport {
            lost_kind,
            lost_domain_id,
            surviving,
            survivor_gate_passed,
        })
    }
}

fn unique_domains(allocations: &[CapacityAllocation], kind: FailureDomainKind) -> usize {
    allocations
        .iter()
        .map(|allocation| failure_domain_id(*allocation, kind))
        .collect::<BTreeSet<_>>()
        .len()
}

fn failure_domain_id(allocation: CapacityAllocation, kind: FailureDomainKind) -> Hash32 {
    match kind {
        FailureDomainKind::ControlCluster => allocation.control_cluster,
        FailureDomainKind::CloudAccount => allocation.cloud_account,
        FailureDomainKind::Asn => allocation.asn_root,
        FailureDomainKind::Region => allocation.region,
        FailureDomainKind::SoftwareLineage => allocation.software_lineage,
        FailureDomainKind::ModelPublisher => allocation.model_publisher,
        FailureDomainKind::BeneficialOwner => allocation.beneficial_owner,
        FailureDomainKind::InfrastructureProvider => allocation.infrastructure_provider,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObligationKind {
    Job = 0,
    CustodyRetention = 1,
    Repair = 2,
    ChallengeReferee = 3,
    Sponsor = 4,
}

impl ObligationKind {
    #[must_use]
    pub const fn bucket(self) -> FundBucketTag {
        match self {
            Self::Job => FundBucketTag::Job,
            Self::CustodyRetention => FundBucketTag::CustodyRetention,
            Self::Repair => FundBucketTag::Repair,
            Self::ChallengeReferee => FundBucketTag::ChallengeReferee,
            Self::Sponsor => FundBucketTag::Sponsor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationRequest {
    pub obligation_id: Hash32,
    pub kind: ObligationKind,
    pub amount: u128,
    pub expected_prior_settlement_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedObligation {
    pub obligation_id: Hash32,
    pub profile_id: Hash32,
    pub bucket: FundBucketTag,
    pub amount: u128,
    pub opening_index: u64,
    pub opened_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObligationSettlement {
    pub obligation: PinnedObligation,
    pub paid: u128,
    pub refunded: u128,
    pub released: u128,
    pub settlement_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundAccount {
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundRowView {
    pub policy: CoveragePolicyRowV1,
    pub ledger: FundLedgerRowV1,
    pub required_free_now: Option<u128>,
    pub monetary_headroom: Option<u128>,
    pub runway_blocks: Option<u64>,
    pub alert_days: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundLedgerView {
    pub profile_id: Hash32,
    pub status: FundLedgerStatus,
    pub rows: Vec<FundRowView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundStateSnapshot {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub current_profile_id: Hash32,
    pub profiles: BTreeMap<Hash32, FundProfileV1>,
    pub ledgers: BTreeMap<Hash32, WwmFundLedgerV1>,
    pub accounts: BTreeMap<Hash32, FundAccount>,
    pub obligations: BTreeMap<(Hash32, Hash32), PinnedObligation>,
    pub consumed_obligations: BTreeSet<(Hash32, Hash32)>,
    pub mutation_locks: BTreeMap<Hash32, FundMutationLockV1>,
    pub wwm_held_total: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundAccountingState {
    chain_id: Hash32,
    genesis_hash: Hash32,
    current_profile_id: Hash32,
    profiles: BTreeMap<Hash32, FundProfileV1>,
    ledgers: BTreeMap<Hash32, WwmFundLedgerV1>,
    accounts: BTreeMap<Hash32, FundAccount>,
    obligations: BTreeMap<(Hash32, Hash32), PinnedObligation>,
    consumed_obligations: BTreeSet<(Hash32, Hash32)>,
    mutation_locks: BTreeMap<Hash32, FundMutationLockV1>,
    wwm_held_total: u128,
}

pub fn validate_fund_profile(
    profile: &FundProfileV1,
    production_capable: bool,
) -> Result<(), WwmEconomicsError> {
    if !profile.validate()
        || [
            profile.profile_id,
            profile.settlement_asset,
            profile.authority_root,
            profile.recovery_root,
            profile.route_root,
        ]
        .contains(&[0; 32])
        || profile.coverage_policy_rows.len() != FUND_BUCKET_COUNT
        || (production_capable && profile.signatures.is_empty())
    {
        return Err(WwmEconomicsError::InvalidFundProfile);
    }
    for policy in profile.coverage_policy_rows.iter() {
        let span = policy
            .coverage_end_height
            .checked_sub(policy.coverage_origin_height)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        policy
            .liability_rate_per_height
            .checked_mul(u128::from(span))
            .and_then(|growth| policy.baseline_liability_at_origin.checked_add(growth))
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        let minimum_end = policy
            .coverage_origin_height
            .checked_add(policy.minimum_coverage_heights)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        if minimum_end > policy.coverage_end_height
            || policy.per_reservation_cap == 0
            || policy.exposure_cap < policy.per_reservation_cap
            || (production_capable
                && (policy.baseline_liability_at_origin == 0
                    || policy.minimum_coverage_heights == 0
                    || policy.coverage_origin_height == policy.coverage_end_height))
        {
            return Err(WwmEconomicsError::InvalidFundProfile);
        }
    }
    Ok(())
}

pub fn required_free_at(
    policy: &CoveragePolicyRowV1,
    height: u64,
) -> Result<u128, WwmEconomicsError> {
    if height < policy.coverage_origin_height || height > policy.coverage_end_height {
        return Err(WwmEconomicsError::ReservationAdmissionFailed);
    }
    let offset = height
        .checked_sub(policy.coverage_origin_height)
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
    policy
        .liability_rate_per_height
        .checked_mul(u128::from(offset))
        .and_then(|growth| policy.baseline_liability_at_origin.checked_add(growth))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)
}

pub fn funded_through_height(
    policy: &CoveragePolicyRowV1,
    free: u128,
) -> Result<Option<u64>, WwmEconomicsError> {
    let span_u64 = policy
        .coverage_end_height
        .checked_sub(policy.coverage_origin_height)
        .ok_or(WwmEconomicsError::InvalidFundProfile)?;
    policy
        .liability_rate_per_height
        .checked_mul(u128::from(span_u64))
        .and_then(|growth| policy.baseline_liability_at_origin.checked_add(growth))
        .ok_or(WwmEconomicsError::InvalidFundProfile)?;
    if free < policy.baseline_liability_at_origin {
        return Ok(None);
    }
    if policy.liability_rate_per_height == 0 {
        return Ok(Some(policy.coverage_end_height));
    }
    let quotient = free
        .checked_sub(policy.baseline_liability_at_origin)
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?
        / policy.liability_rate_per_height;
    let offset = quotient.min(u128::from(span_u64));
    let offset_u64 = u64::try_from(offset).map_err(|_| WwmEconomicsError::ArithmeticOverflow)?;
    policy
        .coverage_origin_height
        .checked_add(offset_u64)
        .map(Some)
        .ok_or(WwmEconomicsError::ArithmeticOverflow)
}

pub fn validate_fund_ledger(
    profile: &FundProfileV1,
    ledger: &WwmFundLedgerV1,
) -> Result<(), WwmEconomicsError> {
    validate_fund_profile(profile, false)?;
    if ledger.profile_id != profile.profile_id
        || !ledger.validate()
        || ledger.rows.len() != FUND_BUCKET_COUNT
    {
        return Err(WwmEconomicsError::InvalidFundLedger);
    }
    for (policy, row) in profile.coverage_policy_rows.iter().zip(ledger.rows.iter()) {
        if policy.bucket != row.bucket
            || row.live_liability != row.reserved
            || row.funded_through_height.0 != funded_through_height(policy, row.free)?
        {
            return Err(WwmEconomicsError::InvalidFundLedger);
        }
        let left = row
            .deposits
            .checked_add(row.migrated_in)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let right = row
            .spent
            .checked_add(row.migrated_out)
            .and_then(|value| value.checked_add(row.reserved))
            .and_then(|value| value.checked_add(row.free))
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        if left != right
            || (ledger.status == FundLedgerStatus::Closed
                && (row.free != 0 || row.reserved != 0 || row.live_liability != 0))
        {
            return Err(WwmEconomicsError::InvalidFundLedger);
        }
    }
    Ok(())
}

fn profile_policy(
    profile: &FundProfileV1,
    bucket: FundBucketTag,
) -> Result<&CoveragePolicyRowV1, WwmEconomicsError> {
    profile
        .coverage_policy_rows
        .as_slice()
        .get(bucket as usize)
        .filter(|row| row.bucket == bucket)
        .ok_or(WwmEconomicsError::InvalidFundProfile)
}

fn ledger_row(
    ledger: &WwmFundLedgerV1,
    bucket: FundBucketTag,
) -> Result<&FundLedgerRowV1, WwmEconomicsError> {
    ledger
        .rows
        .as_slice()
        .get(bucket as usize)
        .filter(|row| row.bucket == bucket)
        .ok_or(WwmEconomicsError::InvalidFundLedger)
}

fn replace_ledger_rows(
    ledger: &mut WwmFundLedgerV1,
    rows: Vec<FundLedgerRowV1>,
) -> Result<(), WwmEconomicsError> {
    ledger.rows = BoundedList::new(rows).ok_or(WwmEconomicsError::InvalidFundLedger)?;
    Ok(())
}

fn ledger_root(ledger: &WwmFundLedgerV1) -> Hash32 {
    noos_lumen::domain_hash("NOOS/WWM/FUND-LEDGER/V1", &[&ledger.encode_canonical()])
}

fn prospective_row(
    policy: &CoveragePolicyRowV1,
    row: &FundLedgerRowV1,
    height: u64,
    amount: u128,
) -> Result<FundLedgerRowV1, WwmEconomicsError> {
    if amount == 0 || amount > policy.per_reservation_cap {
        return Err(WwmEconomicsError::ReservationAdmissionFailed);
    }
    let target = height
        .checked_add(policy.minimum_coverage_heights)
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
    if height < policy.coverage_origin_height || target > policy.coverage_end_height {
        return Err(WwmEconomicsError::ReservationAdmissionFailed);
    }
    let free = row
        .free
        .checked_sub(amount)
        .ok_or(WwmEconomicsError::ReservationAdmissionFailed)?;
    let reserved = row
        .reserved
        .checked_add(amount)
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
    if reserved > policy.exposure_cap {
        return Err(WwmEconomicsError::ReservationAdmissionFailed);
    }
    let funded = funded_through_height(policy, free)?;
    if funded.is_none_or(|through| through < target) {
        return Err(WwmEconomicsError::ReservationAdmissionFailed);
    }
    Ok(FundLedgerRowV1 {
        bucket: row.bucket,
        deposits: row.deposits,
        migrated_in: row.migrated_in,
        spent: row.spent,
        migrated_out: row.migrated_out,
        reserved,
        free,
        live_liability: reserved,
        funded_through_height: OptionalU64(funded),
        settlement_index: row
            .settlement_index
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?,
    })
}

impl FundAccountingState {
    pub fn new(chain_id: Hash32, genesis_hash: Hash32) -> Result<Self, WwmEconomicsError> {
        if chain_id == [0; 32] || genesis_hash == [0; 32] {
            return Err(WwmEconomicsError::InvalidFundProfile);
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            current_profile_id: [0; 32],
            profiles: BTreeMap::new(),
            ledgers: BTreeMap::new(),
            accounts: BTreeMap::new(),
            obligations: BTreeMap::new(),
            consumed_obligations: BTreeSet::new(),
            mutation_locks: BTreeMap::new(),
            wwm_held_total: 0,
        })
    }

    pub fn install_genesis(
        &mut self,
        profile: FundProfileV1,
        production_capable: bool,
    ) -> Result<(), WwmEconomicsError> {
        if !self.profiles.is_empty()
            || !self.ledgers.is_empty()
            || self.current_profile_id != [0; 32]
            || self.wwm_held_total != 0
        {
            return Err(WwmEconomicsError::InvalidFundProfile);
        }
        validate_fund_profile(&profile, production_capable)?;
        let ledger = genesis_fund_ledger(&profile).ok_or(WwmEconomicsError::InvalidFundLedger)?;
        validate_fund_ledger(&profile, &ledger)?;
        self.current_profile_id = profile.profile_id;
        self.ledgers.insert(profile.profile_id, ledger);
        self.profiles.insert(profile.profile_id, profile);
        Ok(())
    }

    pub fn stage_profile(
        &mut self,
        profile: FundProfileV1,
        production_capable: bool,
    ) -> Result<(), WwmEconomicsError> {
        validate_fund_profile(&profile, production_capable)?;
        if self.current_profile_id == [0; 32]
            || self.profiles.contains_key(&profile.profile_id)
            || self.ledgers.contains_key(&profile.profile_id)
        {
            return Err(WwmEconomicsError::InvalidFundProfile);
        }
        let rows = profile
            .coverage_policy_rows
            .iter()
            .map(|policy| {
                Ok(FundLedgerRowV1 {
                    bucket: policy.bucket,
                    deposits: 0,
                    migrated_in: 0,
                    spent: 0,
                    migrated_out: 0,
                    reserved: 0,
                    free: 0,
                    live_liability: 0,
                    funded_through_height: OptionalU64(funded_through_height(policy, 0)?),
                    settlement_index: 0,
                })
            })
            .collect::<Result<Vec<_>, WwmEconomicsError>>()?;
        let ledger = WwmFundLedgerV1 {
            profile_id: profile.profile_id,
            status: FundLedgerStatus::Staged,
            rows: BoundedList::new(rows).ok_or(WwmEconomicsError::InvalidFundLedger)?,
            topup_permit_epoch: 0,
            lock_ref: OptionalObject(None),
        };
        validate_fund_ledger(&profile, &ledger)?;
        self.ledgers.insert(profile.profile_id, ledger);
        self.profiles.insert(profile.profile_id, profile);
        Ok(())
    }

    pub fn credit_account(
        &mut self,
        account_id: Hash32,
        amount: u128,
    ) -> Result<(), WwmEconomicsError> {
        if account_id == [0; 32] || amount == 0 {
            return Err(WwmEconomicsError::InsufficientAccountBalance);
        }
        let prior = self
            .accounts
            .get(&account_id)
            .copied()
            .unwrap_or(FundAccount {
                balance: 0,
                nonce: 0,
            });
        let balance = prior
            .balance
            .checked_add(amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        self.accounts.insert(
            account_id,
            FundAccount {
                balance,
                nonce: prior.nonce,
            },
        );
        Ok(())
    }

    pub fn top_up(
        &mut self,
        permit: &FundTopUpPermitV1,
        height: u64,
        verify_authority: impl FnOnce(&FundTopUpPermitV1) -> bool,
    ) -> Result<(), WwmEconomicsError> {
        if permit.chain_id != self.chain_id
            || permit.genesis_hash != self.genesis_hash
            || permit.amount == 0
            || permit.issued_height > permit.not_before_height
            || permit.not_before_height > height
            || height >= permit.expiry_height
            || permit.signature.as_slice().is_empty()
            || !verify_authority(permit)
        {
            return Err(WwmEconomicsError::InvalidFundPermit);
        }
        let profile = self
            .profiles
            .get(&permit.profile_id)
            .ok_or(WwmEconomicsError::InvalidFundPermit)?;
        let ledger = self
            .ledgers
            .get(&permit.profile_id)
            .ok_or(WwmEconomicsError::InvalidFundPermit)?;
        validate_fund_ledger(profile, ledger)?;
        if ledger.status == FundLedgerStatus::Closed
            || ledger.lock_ref.0.is_some()
            || permit.permit_epoch != ledger.topup_permit_epoch
            || fund_route_key(&permit.profile_id, permit.bucket) == permit.payer
            || self
                .accounts
                .contains_key(&fund_route_key(&permit.profile_id, permit.bucket))
        {
            return Err(WwmEconomicsError::InvalidFundPermit);
        }
        let account = self
            .accounts
            .get(&permit.payer)
            .copied()
            .ok_or(WwmEconomicsError::InsufficientAccountBalance)?;
        if account.nonce != permit.prior_account_nonce || account.balance < permit.amount {
            return Err(WwmEconomicsError::InvalidFundPermit);
        }
        let mut rows = ledger.rows.as_slice().to_vec();
        let row = rows
            .get_mut(permit.bucket as usize)
            .filter(|row| row.bucket == permit.bucket)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        let policy = profile_policy(profile, permit.bucket)?;
        row.deposits = row
            .deposits
            .checked_add(permit.amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        row.free = row
            .free
            .checked_add(permit.amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        row.settlement_index = row
            .settlement_index
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        row.funded_through_height = OptionalU64(funded_through_height(policy, row.free)?);
        let next_nonce = account
            .nonce
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let next_balance = account
            .balance
            .checked_sub(permit.amount)
            .ok_or(WwmEconomicsError::InsufficientAccountBalance)?;
        let next_held = self
            .wwm_held_total
            .checked_add(permit.amount)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let mut next_ledger = ledger.clone();
        replace_ledger_rows(&mut next_ledger, rows)?;
        validate_fund_ledger(profile, &next_ledger)?;
        self.accounts.insert(
            permit.payer,
            FundAccount {
                balance: next_balance,
                nonce: next_nonce,
            },
        );
        self.wwm_held_total = next_held;
        self.ledgers.insert(permit.profile_id, next_ledger);
        Ok(())
    }

    pub fn reserve_many(
        &mut self,
        profile_id: Hash32,
        height: u64,
        requests: &[ReservationRequest],
    ) -> Result<Vec<PinnedObligation>, WwmEconomicsError> {
        if requests.is_empty()
            || requests.len() > FUND_BUCKET_COUNT
            || !strictly_sorted_by(requests, |request| request.kind.bucket())
            || requests.iter().any(|request| {
                request.obligation_id == [0; 32]
                    || request.amount == 0
                    || self
                        .obligations
                        .contains_key(&(profile_id, request.obligation_id))
                    || self
                        .consumed_obligations
                        .contains(&(profile_id, request.obligation_id))
            })
        {
            return Err(WwmEconomicsError::InvalidObligation);
        }
        let profile = self
            .profiles
            .get(&profile_id)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        let ledger = self
            .ledgers
            .get(&profile_id)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        validate_fund_ledger(profile, ledger)?;
        if ledger.status != FundLedgerStatus::Current || ledger.lock_ref.0.is_some() {
            return Err(WwmEconomicsError::ReservationAdmissionFailed);
        }
        let mut prospective_rows = ledger.rows.as_slice().to_vec();
        let mut obligations = Vec::with_capacity(requests.len());
        for request in requests {
            let bucket = request.kind.bucket();
            let prior = prospective_rows
                .get(bucket as usize)
                .cloned()
                .ok_or(WwmEconomicsError::InvalidFundLedger)?;
            if prior.bucket != bucket
                || prior.settlement_index != request.expected_prior_settlement_index
            {
                return Err(WwmEconomicsError::ReservationAdmissionFailed);
            }
            let policy = profile_policy(profile, bucket)?;
            let next = prospective_row(policy, &prior, height, request.amount)?;
            prospective_rows[bucket as usize] = next.clone();
            obligations.push(PinnedObligation {
                obligation_id: request.obligation_id,
                profile_id,
                bucket,
                amount: request.amount,
                opening_index: next.settlement_index,
                opened_height: height,
            });
        }
        let mut next_ledger = ledger.clone();
        replace_ledger_rows(&mut next_ledger, prospective_rows)?;
        validate_fund_ledger(profile, &next_ledger)?;
        self.ledgers.insert(profile_id, next_ledger);
        for obligation in &obligations {
            self.obligations
                .insert((profile_id, obligation.obligation_id), *obligation);
        }
        Ok(obligations)
    }

    pub fn settle_obligation(
        &mut self,
        profile_id: Hash32,
        obligation_id: Hash32,
        paid: u128,
        refunded: u128,
        released: u128,
    ) -> Result<ObligationSettlement, WwmEconomicsError> {
        let key = (profile_id, obligation_id);
        if self.consumed_obligations.contains(&key) {
            return Err(WwmEconomicsError::ObligationAlreadyConsumed);
        }
        let obligation = self
            .obligations
            .get(&key)
            .copied()
            .ok_or(WwmEconomicsError::UnknownObligation)?;
        let consumed = paid
            .checked_add(refunded)
            .and_then(|value| value.checked_add(released))
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        if consumed != obligation.amount {
            return Err(WwmEconomicsError::InvalidSettlement);
        }
        let profile = self
            .profiles
            .get(&profile_id)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        let ledger = self
            .ledgers
            .get(&profile_id)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        validate_fund_ledger(profile, ledger)?;
        if ledger.lock_ref.0.is_some()
            || !matches!(
                ledger.status,
                FundLedgerStatus::Current | FundLedgerStatus::Superseded
            )
        {
            return Err(WwmEconomicsError::InvalidFundLedger);
        }
        let external = paid
            .checked_add(refunded)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        let mut rows = ledger.rows.as_slice().to_vec();
        let row = rows
            .get_mut(obligation.bucket as usize)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        row.reserved = row
            .reserved
            .checked_sub(obligation.amount)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        row.live_liability = row
            .live_liability
            .checked_sub(obligation.amount)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        row.spent = row
            .spent
            .checked_add(external)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        row.free = row
            .free
            .checked_add(released)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        row.settlement_index = row
            .settlement_index
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        row.funded_through_height = OptionalU64(funded_through_height(
            profile_policy(profile, obligation.bucket)?,
            row.free,
        )?);
        let next_held = self
            .wwm_held_total
            .checked_sub(external)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        let settlement_index = row.settlement_index;
        let mut next_ledger = ledger.clone();
        replace_ledger_rows(&mut next_ledger, rows)?;
        validate_fund_ledger(profile, &next_ledger)?;
        self.ledgers.insert(profile_id, next_ledger);
        self.wwm_held_total = next_held;
        self.consumed_obligations.insert(key);
        self.obligations.remove(&key);
        Ok(ObligationSettlement {
            obligation,
            paid,
            refunded,
            released,
            settlement_index,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn lock_mutation(
        &mut self,
        operation: FundMutationOperation,
        source_profile_id: Hash32,
        other_profile_id: Hash32,
        lock_id: Hash32,
        current_height: u64,
        execute_before_height: u64,
        authority_epoch: u64,
        signature: Vec<u8>,
    ) -> Result<FundMutationLockV1, WwmEconomicsError> {
        if lock_id == [0; 32]
            || source_profile_id == other_profile_id
            || current_height >= execute_before_height
            || signature.is_empty()
            || self.mutation_locks.values().any(|lock| {
                lock.status == FundMutationLockStatus::Pending
                    && current_height < lock.execute_before_height
            })
        {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        let source = self
            .ledgers
            .get(&source_profile_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        let other = self
            .ledgers
            .get(&other_profile_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        validate_fund_ledger(
            self.profiles
                .get(&source_profile_id)
                .ok_or(WwmEconomicsError::InvalidFundProfile)?,
            &source,
        )?;
        validate_fund_ledger(
            self.profiles
                .get(&other_profile_id)
                .ok_or(WwmEconomicsError::InvalidFundProfile)?,
            &other,
        )?;
        if source.lock_ref.0.is_some()
            || other.lock_ref.0.is_some()
            || match operation {
                FundMutationOperation::Activate => {
                    source_profile_id != self.current_profile_id
                        || source.status != FundLedgerStatus::Current
                        || other.status != FundLedgerStatus::Staged
                }
                FundMutationOperation::Close => {
                    other_profile_id != self.current_profile_id
                        || other.status != FundLedgerStatus::Current
                        || !matches!(
                            source.status,
                            FundLedgerStatus::Staged | FundLedgerStatus::Superseded
                        )
                }
            }
        {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        let mut source_locked = source.clone();
        let mut other_locked = other.clone();
        source_locked.topup_permit_epoch = source_locked
            .topup_permit_epoch
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        other_locked.topup_permit_epoch = other_locked
            .topup_permit_epoch
            .checked_add(1)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        source_locked.lock_ref = OptionalObject(Some(FundMutationLockRefV1 {
            lock_id,
            operation,
            peer_profile_id: other_profile_id,
            execute_before_height,
        }));
        other_locked.lock_ref = OptionalObject(Some(FundMutationLockRefV1 {
            lock_id,
            operation,
            peer_profile_id: source_profile_id,
            execute_before_height,
        }));
        let source_root = ledger_root(&source_locked);
        let other_root = ledger_root(&other_locked);
        let (
            profile_id_0,
            profile_id_1,
            post_ref_root_0,
            post_ref_root_1,
            permit_epoch_0,
            permit_epoch_1,
        ) = if source_profile_id < other_profile_id {
            (
                source_profile_id,
                other_profile_id,
                source_root,
                other_root,
                source_locked.topup_permit_epoch,
                other_locked.topup_permit_epoch,
            )
        } else {
            (
                other_profile_id,
                source_profile_id,
                other_root,
                source_root,
                other_locked.topup_permit_epoch,
                source_locked.topup_permit_epoch,
            )
        };
        let lock = FundMutationLockV1 {
            lock_id,
            operation,
            profile_id_0,
            profile_id_1,
            post_ref_root_0,
            post_ref_root_1,
            permit_epoch_0,
            permit_epoch_1,
            authority_epoch,
            execute_before_height,
            status: FundMutationLockStatus::Pending,
            signature: BoundedBytes::new(signature).ok_or(WwmEconomicsError::InvalidFundLock)?,
        };
        self.ledgers.insert(source_profile_id, source_locked);
        self.ledgers.insert(other_profile_id, other_locked);
        self.mutation_locks.insert(lock_id, lock.clone());
        Ok(lock)
    }

    pub fn activate_successor(
        &mut self,
        lock_id: Hash32,
        height: u64,
    ) -> Result<(), WwmEconomicsError> {
        let lock = self
            .mutation_locks
            .get(&lock_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        if lock.operation != FundMutationOperation::Activate
            || lock.status != FundMutationLockStatus::Pending
            || height >= lock.execute_before_height
        {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        let current_id = self.current_profile_id;
        let candidate_id = if lock.profile_id_0 == current_id {
            lock.profile_id_1
        } else if lock.profile_id_1 == current_id {
            lock.profile_id_0
        } else {
            return Err(WwmEconomicsError::InvalidFundLock);
        };
        let mut current = self
            .ledgers
            .get(&current_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        let mut candidate = self
            .ledgers
            .get(&candidate_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        if current.status != FundLedgerStatus::Current
            || candidate.status != FundLedgerStatus::Staged
            || !lock_roots_match(&lock, &current, &candidate)
            || !ledger_horizon_valid(
                self.profiles
                    .get(&candidate_id)
                    .ok_or(WwmEconomicsError::InvalidFundProfile)?,
                &candidate,
                height,
            )?
        {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        current.status = FundLedgerStatus::Superseded;
        candidate.status = FundLedgerStatus::Current;
        current.lock_ref = OptionalObject(None);
        candidate.lock_ref = OptionalObject(None);
        self.current_profile_id = candidate_id;
        self.ledgers.insert(current_id, current);
        self.ledgers.insert(candidate_id, candidate);
        let stored = self
            .mutation_locks
            .get_mut(&lock_id)
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        stored.status = FundMutationLockStatus::Completed;
        Ok(())
    }

    pub fn close_profile(&mut self, lock_id: Hash32, height: u64) -> Result<(), WwmEconomicsError> {
        let lock = self
            .mutation_locks
            .get(&lock_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        if lock.operation != FundMutationOperation::Close
            || lock.status != FundMutationLockStatus::Pending
            || height >= lock.execute_before_height
        {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        let current_id = self.current_profile_id;
        let source_id = if lock.profile_id_0 == current_id {
            lock.profile_id_1
        } else if lock.profile_id_1 == current_id {
            lock.profile_id_0
        } else {
            return Err(WwmEconomicsError::InvalidFundLock);
        };
        let mut source = self
            .ledgers
            .get(&source_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        let mut current = self
            .ledgers
            .get(&current_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        if !matches!(
            source.status,
            FundLedgerStatus::Staged | FundLedgerStatus::Superseded
        ) || current.status != FundLedgerStatus::Current
            || !lock_roots_match(&lock, &source, &current)
            || source
                .rows
                .iter()
                .any(|row| row.reserved != 0 || row.live_liability != 0)
        {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        let source_profile = self
            .profiles
            .get(&source_id)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        let current_profile = self
            .profiles
            .get(&current_id)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        let mut source_rows = source.rows.as_slice().to_vec();
        let mut current_rows = current.rows.as_slice().to_vec();
        for bucket_index in 0..FUND_BUCKET_COUNT {
            let amount = source_rows[bucket_index].free;
            source_rows[bucket_index].free = 0;
            source_rows[bucket_index].migrated_out = source_rows[bucket_index]
                .migrated_out
                .checked_add(amount)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
            source_rows[bucket_index].settlement_index = source_rows[bucket_index]
                .settlement_index
                .checked_add(1)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
            source_rows[bucket_index].funded_through_height = OptionalU64(funded_through_height(
                &source_profile.coverage_policy_rows.as_slice()[bucket_index],
                0,
            )?);
            current_rows[bucket_index].free = current_rows[bucket_index]
                .free
                .checked_add(amount)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
            current_rows[bucket_index].migrated_in = current_rows[bucket_index]
                .migrated_in
                .checked_add(amount)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
            current_rows[bucket_index].settlement_index = current_rows[bucket_index]
                .settlement_index
                .checked_add(1)
                .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
            current_rows[bucket_index].funded_through_height = OptionalU64(funded_through_height(
                &current_profile.coverage_policy_rows.as_slice()[bucket_index],
                current_rows[bucket_index].free,
            )?);
        }
        source.status = FundLedgerStatus::Closed;
        current.lock_ref = OptionalObject(None);
        source.lock_ref = OptionalObject(None);
        replace_ledger_rows(&mut source, source_rows)?;
        replace_ledger_rows(&mut current, current_rows)?;
        validate_fund_ledger(source_profile, &source)?;
        validate_fund_ledger(current_profile, &current)?;
        self.ledgers.insert(source_id, source);
        self.ledgers.insert(current_id, current);
        let stored = self
            .mutation_locks
            .get_mut(&lock_id)
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        stored.status = FundMutationLockStatus::Completed;
        Ok(())
    }

    pub fn expire_lock(&mut self, lock_id: Hash32, height: u64) -> Result<(), WwmEconomicsError> {
        let lock = self
            .mutation_locks
            .get(&lock_id)
            .cloned()
            .ok_or(WwmEconomicsError::InvalidFundLock)?;
        if lock.status != FundMutationLockStatus::Pending || height < lock.execute_before_height {
            return Err(WwmEconomicsError::InvalidFundLock);
        }
        for profile_id in [lock.profile_id_0, lock.profile_id_1] {
            let ledger = self
                .ledgers
                .get_mut(&profile_id)
                .ok_or(WwmEconomicsError::InvalidFundLock)?;
            if ledger
                .lock_ref
                .0
                .as_ref()
                .is_none_or(|reference| reference.lock_id != lock_id)
            {
                return Err(WwmEconomicsError::InvalidFundLock);
            }
            ledger.lock_ref = OptionalObject(None);
        }
        self.mutation_locks
            .get_mut(&lock_id)
            .ok_or(WwmEconomicsError::InvalidFundLock)?
            .status = FundMutationLockStatus::Expired;
        Ok(())
    }

    pub fn view(
        &self,
        profile_id: Hash32,
        height: u64,
        blocks_per_day: u64,
    ) -> Result<FundLedgerView, WwmEconomicsError> {
        let profile = self
            .profiles
            .get(&profile_id)
            .ok_or(WwmEconomicsError::InvalidFundProfile)?;
        let ledger = self
            .ledgers
            .get(&profile_id)
            .ok_or(WwmEconomicsError::InvalidFundLedger)?;
        validate_fund_ledger(profile, ledger)?;
        let mut rows = Vec::with_capacity(FUND_BUCKET_COUNT);
        for (policy, row) in profile.coverage_policy_rows.iter().zip(ledger.rows.iter()) {
            let required_free_now = if height >= policy.coverage_origin_height
                && height <= policy.coverage_end_height
            {
                Some(required_free_at(policy, height)?)
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
                            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
                        if runway <= threshold {
                            alert_days.push(days);
                        }
                    }
                } else {
                    alert_days.extend([30, 14, 7, 3, 1]);
                }
            }
            rows.push(FundRowView {
                policy: policy.clone(),
                ledger: row.clone(),
                required_free_now,
                monetary_headroom,
                runway_blocks,
                alert_days,
            });
        }
        Ok(FundLedgerView {
            profile_id,
            status: ledger.status,
            rows,
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> FundStateSnapshot {
        FundStateSnapshot {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            current_profile_id: self.current_profile_id,
            profiles: self.profiles.clone(),
            ledgers: self.ledgers.clone(),
            accounts: self.accounts.clone(),
            obligations: self.obligations.clone(),
            consumed_obligations: self.consumed_obligations.clone(),
            mutation_locks: self.mutation_locks.clone(),
            wwm_held_total: self.wwm_held_total,
        }
    }

    pub fn restore_snapshot(
        &mut self,
        snapshot: FundStateSnapshot,
    ) -> Result<(), WwmEconomicsError> {
        let rebuilt = snapshot_rebuild_held_total(&snapshot.ledgers)?;
        if snapshot.chain_id != self.chain_id
            || snapshot.genesis_hash != self.genesis_hash
            || rebuilt != snapshot.wwm_held_total
            || snapshot
                .ledgers
                .get(&snapshot.current_profile_id)
                .is_none_or(|ledger| ledger.status != FundLedgerStatus::Current)
            || snapshot.ledgers.iter().any(|(id, ledger)| {
                snapshot
                    .profiles
                    .get(id)
                    .is_none_or(|profile| validate_fund_ledger(profile, ledger).is_err())
            })
        {
            return Err(WwmEconomicsError::InvalidFundLedger);
        }
        self.current_profile_id = snapshot.current_profile_id;
        self.profiles = snapshot.profiles;
        self.ledgers = snapshot.ledgers;
        self.accounts = snapshot.accounts;
        self.obligations = snapshot.obligations;
        self.consumed_obligations = snapshot.consumed_obligations;
        self.mutation_locks = snapshot.mutation_locks;
        self.wwm_held_total = snapshot.wwm_held_total;
        Ok(())
    }

    #[must_use]
    pub fn current_profile_id(&self) -> Hash32 {
        self.current_profile_id
    }

    #[must_use]
    pub fn account(&self, account_id: Hash32) -> Option<FundAccount> {
        self.accounts.get(&account_id).copied()
    }

    #[must_use]
    pub const fn wwm_held_total(&self) -> u128 {
        self.wwm_held_total
    }

    #[must_use]
    pub fn ledger(&self, profile_id: Hash32) -> Option<&WwmFundLedgerV1> {
        self.ledgers.get(&profile_id)
    }
}

fn ledger_horizon_valid(
    profile: &FundProfileV1,
    ledger: &WwmFundLedgerV1,
    height: u64,
) -> Result<bool, WwmEconomicsError> {
    validate_fund_ledger(profile, ledger)?;
    for (policy, row) in profile.coverage_policy_rows.iter().zip(ledger.rows.iter()) {
        let target = height
            .checked_add(policy.minimum_coverage_heights)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
        if height < policy.coverage_origin_height
            || target > policy.coverage_end_height
            || row
                .funded_through_height
                .0
                .is_none_or(|through| through < target)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn lock_roots_match(
    lock: &FundMutationLockV1,
    first: &WwmFundLedgerV1,
    second: &WwmFundLedgerV1,
) -> bool {
    let roots = BTreeMap::from([
        (first.profile_id, ledger_root(first)),
        (second.profile_id, ledger_root(second)),
    ]);
    roots.get(&lock.profile_id_0) == Some(&lock.post_ref_root_0)
        && roots.get(&lock.profile_id_1) == Some(&lock.post_ref_root_1)
}

pub fn snapshot_rebuild_held_total(
    ledgers: &BTreeMap<Hash32, WwmFundLedgerV1>,
) -> Result<u128, WwmEconomicsError> {
    ledgers.values().try_fold(0_u128, |total, ledger| {
        let held = ledger.rows.iter().try_fold(0_u128, |row_total, row| {
            row.reserved
                .checked_add(row.free)
                .and_then(|value| row_total.checked_add(value))
                .ok_or(WwmEconomicsError::ArithmeticOverflow)
        })?;
        total
            .checked_add(held)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)
    })
}

fn encode_fee_schedule(out: &mut Vec<u8>, schedule: FeeSchedule) {
    out.extend(schedule.cold_load_fee.to_le_bytes());
    out.extend(schedule.resident_load_fee.to_le_bytes());
    out.extend(schedule.prefill_token_rate.to_le_bytes());
    out.extend(schedule.decode_token_rate.to_le_bytes());
    out.extend(schedule.evidence_byte_rate.to_le_bytes());
    out.extend(schedule.verification_unit_rate.to_le_bytes());
    out.extend(schedule.privacy_premium.to_le_bytes());
    out.extend(schedule.route_byte_rate.to_le_bytes());
    out.extend(schedule.storage_byte_epoch_rate.to_le_bytes());
}

fn encode_usage(out: &mut Vec<u8>, usage: FeeUsage) {
    out.extend(usage.prefill_tokens.to_le_bytes());
    out.extend(usage.decode_tokens.to_le_bytes());
    out.extend(usage.evidence_bytes.to_le_bytes());
    out.extend(usage.verification_units.to_le_bytes());
    out.extend(usage.route_bytes.to_le_bytes());
    out.extend(usage.storage_bytes.to_le_bytes());
    out.extend(usage.retention_epochs.to_le_bytes());
}

fn push_payment(
    payments: &mut Vec<RolePayment>,
    role: SettlementRole,
    account: Hash32,
    amount: u128,
) -> Result<(), WwmEconomicsError> {
    if account == [0; 32] {
        return Err(WwmEconomicsError::InvalidSettlement);
    }
    if amount != 0 {
        payments.push(RolePayment {
            role,
            account,
            amount,
        });
    }
    Ok(())
}

fn multiply(rate: u128, count: u64) -> Result<u128, WwmEconomicsError> {
    rate.checked_mul(u128::from(count))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)
}

fn share(value: u128, bps: u16) -> Result<u128, WwmEconomicsError> {
    value
        .checked_mul(u128::from(bps))
        .and_then(|product| product.checked_div(u128::from(BPS)))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)
}

fn share_bps_ceil(part: u128, total: u128) -> Result<u16, WwmEconomicsError> {
    if total == 0 || part > total {
        return Err(WwmEconomicsError::InvalidConcentrationInput);
    }
    let numerator = part
        .checked_mul(u128::from(BPS))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
    let rounded = numerator
        .checked_add(total.saturating_sub(1))
        .and_then(|value| value.checked_div(total))
        .ok_or(WwmEconomicsError::ArithmeticOverflow)?;
    u16::try_from(rounded).map_err(|_| WwmEconomicsError::ArithmeticOverflow)
}

fn checked_sum(values: impl IntoIterator<Item = u128>) -> Result<u128, WwmEconomicsError> {
    values.into_iter().try_fold(0_u128, |total, value| {
        total
            .checked_add(value)
            .ok_or(WwmEconomicsError::ArithmeticOverflow)
    })
}

fn strictly_sorted_by<T, K: Ord + Copy>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, WwmEconomicsError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| WwmEconomicsError::InvalidSignature)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], WwmEconomicsError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| WwmEconomicsError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), WwmEconomicsError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| WwmEconomicsError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        clippy::unwrap_used
    )]

    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn schedule() -> FeeSchedule {
        FeeSchedule {
            cold_load_fee: 1_000,
            resident_load_fee: 100,
            prefill_token_rate: 2,
            decode_token_rate: 4,
            evidence_byte_rate: 1,
            verification_unit_rate: 10,
            privacy_premium: 50,
            route_byte_rate: 1,
            storage_byte_epoch_rate: 1,
        }
    }

    fn bounds() -> FeeUsage {
        FeeUsage {
            prefill_tokens: 100,
            decode_tokens: 100,
            evidence_bytes: 100,
            verification_units: 10,
            route_bytes: 100,
            storage_bytes: 10,
            retention_epochs: 2,
        }
    }

    fn quote(residency: ResidencyCommitment) -> CapacityQuote {
        CapacityQuote::issue(
            h(1),
            h(2),
            QuoteChainContext {
                chain_id: h(130),
                genesis_hash: h(131),
                execution_profile_id: h(132),
                query_policy_id: h(133),
                fee_policy_id: h(134),
                fund_profile_id: h(135),
                executor_registry_epoch: 7,
                fee_policy_epoch: 8,
                fund_profile_epoch: 9,
            },
            h(3),
            h(4),
            h(5),
            h(6),
            h(7),
            64500,
            residency,
            h(8),
            8,
            100,
            50,
            schedule(),
            bounds(),
            h(9),
            10,
            100,
            h(10),
            &Keypair::from_seed([11; 32]),
        )
        .unwrap()
    }

    fn accounts() -> SettlementAccounts {
        SettlementAccounts {
            executor: h(20),
            custodian: h(21),
            verifier: h(22),
            evaluator: h(23),
            relay: h(24),
            gateway: h(25),
            challenger: h(26),
            refund: h(27),
        }
    }

    fn policy() -> SettlementPolicy {
        SettlementPolicy {
            executor_bps: 5_000,
            custodian_bps: 1_000,
            verifier_bps: 1_000,
            evaluator_bps: 1_000,
            relay_bps: 500,
            gateway_bps: 500,
            dispute_bounty_bps: 2_000,
            policy_root: h(28),
        }
    }

    fn fund_profile(profile_id: Hash32) -> FundProfileV1 {
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
            profile_id,
            settlement_asset: h(211),
            authority_root: h(212),
            recovery_root: h(213),
            route_root: h(214),
            coverage_policy_rows: BoundedList::new(rows).unwrap(),
            authority_epoch: 1,
            signatures: BoundedList::new(vec![noos_lumen::wwm::SignatureEntryV1 {
                signer_id: h(215),
                signature: BoundedBytes::new(vec![1; 64]).unwrap(),
            }])
            .unwrap(),
        }
    }

    fn topup_permit(
        state: &FundAccountingState,
        payer: Hash32,
        profile_id: Hash32,
        bucket: FundBucketTag,
        amount: u128,
    ) -> FundTopUpPermitV1 {
        FundTopUpPermitV1 {
            chain_id: state.chain_id,
            genesis_hash: state.genesis_hash,
            permit_epoch: state.ledger(profile_id).unwrap().topup_permit_epoch,
            payer,
            prior_account_nonce: state.account(payer).unwrap().nonce,
            profile_id,
            bucket,
            amount,
            issued_height: 9,
            not_before_height: 10,
            expiry_height: 100,
            authority_epoch: 1,
            signature: BoundedBytes::new(vec![2; 64]).unwrap(),
        }
    }

    fn prefund_all_rows(
        state: &mut FundAccountingState,
        payer: Hash32,
        profile_id: Hash32,
        amount: u128,
    ) {
        for bucket in [
            FundBucketTag::Job,
            FundBucketTag::CustodyRetention,
            FundBucketTag::Repair,
            FundBucketTag::ChallengeReferee,
            FundBucketTag::Sponsor,
        ] {
            let permit = topup_permit(state, payer, profile_id, bucket, amount);
            state.top_up(&permit, 10, |_| true).unwrap();
        }
    }

    #[test]
    fn signed_capacity_quote_discloses_each_bounded_fee_dimension() {
        let resident = quote(ResidencyCommitment::Resident);
        let cold = quote(ResidencyCommitment::ColdStart);
        resident.validate().unwrap();
        assert!(resident.maximum_fee < cold.maximum_fee);
        let mut over = bounds();
        over.decode_tokens = 101;
        assert_eq!(
            resident.fee_for(over),
            Err(WwmEconomicsError::BoundsExceeded)
        );

        let mut tampered = resident;
        tampered.maximum_concurrent_jobs = 9;
        assert_eq!(tampered.validate(), Err(WwmEconomicsError::InvalidQuote));
    }

    #[test]
    fn settlement_conserves_escrow_refunds_unused_fee_and_uses_no_issuance() {
        let quote = quote(ResidencyCommitment::Resident);
        let mut usage = bounds();
        usage.decode_tokens = 10;
        let settlement = ApplicationSettlement::calculate(
            &quote,
            usage,
            policy(),
            accounts(),
            SettlementVerdict::ValidDelivery,
            h(29),
        )
        .unwrap();
        settlement.validate().unwrap();
        let paid = checked_sum(settlement.payments.iter().map(|payment| payment.amount)).unwrap();
        assert_eq!(paid + settlement.refund_amount, quote.maximum_fee);
        assert_eq!(settlement.issuance, 0);

        let failed = ApplicationSettlement::calculate(
            &quote,
            usage,
            policy(),
            accounts(),
            SettlementVerdict::ObjectiveFailure,
            h(30),
        )
        .unwrap();
        assert!(failed
            .payments
            .iter()
            .any(|payment| payment.role == SettlementRole::Challenger));
        assert!(!failed
            .payments
            .iter()
            .any(|payment| payment.role == SettlementRole::Executor));
    }

    #[test]
    fn sponsor_caps_bind_spend_while_circular_demand_gets_zero_credit() {
        let policy = SponsorPolicy {
            sponsor_id: h(31),
            sponsor_control_cluster: h(32),
            maximum_fee_per_job: 100,
            maximum_daily_spend: 200,
            maximum_daily_jobs: 2,
            maximum_total_spend: 1_000,
            policy_root: h(33),
        };
        let mut book = SponsorBook::default();
        book.prefund(policy, 1_000).unwrap();
        let circular = book
            .reserve(
                policy,
                h(34),
                100,
                1,
                FundingClassification::CircularFunding,
                h(37),
            )
            .unwrap();
        assert_eq!(circular.production_credit, 0);
        book.reserve(
            policy,
            h(35),
            100,
            1,
            FundingClassification::IndependentlyFunded,
            h(38),
        )
        .unwrap();
        assert_eq!(
            book.reserve(
                policy,
                h(36),
                1,
                1,
                FundingClassification::IndependentlyFunded,
                h(39),
            ),
            Err(WwmEconomicsError::SponsorCapExceeded)
        );
        assert!(!WWM_APPLICATION_CREDIT_ENABLED);
    }

    #[test]
    fn concentration_gate_enforces_twenty_percent_and_survivor_quarter_laws() {
        let mut balanced = Vec::new();
        for index in 0..5_u8 {
            balanced.push(CapacityAllocation {
                quote_id: h(40 + index),
                control_cluster: h(50 + index),
                cloud_account: h(60 + index),
                asn_root: h(70 + index),
                region: h(80 + index),
                software_lineage: h(90 + index),
                model_publisher: h(100 + index),
                beneficial_owner: h(110 + index),
                infrastructure_provider: h(120 + index),
                selection_weight: 20,
                custody_bytes: 20,
            });
        }
        let report = ConcentrationReport::build(&balanced).unwrap();
        assert!(report.steady_gate_passed);
        assert_eq!(report.independent_control_clusters, 5);
        assert_eq!(report.independent_regions, 5);
        let survivor =
            ConcentrationReport::after_largest_domain_loss(&balanced, FailureDomainKind::Region)
                .unwrap();
        assert!(survivor.survivor_gate_passed);

        balanced[0].selection_weight = 80;
        balanced[1].custody_bytes = 80;
        let concentrated = ConcentrationReport::build(&balanced).unwrap();
        assert!(!concentrated.steady_gate_passed);
        let control_peak = concentrated
            .peaks
            .iter()
            .find(|peak| peak.kind == FailureDomainKind::ControlCluster)
            .unwrap();
        assert_eq!(control_peak.selection_domain_id, h(50));
        assert_eq!(control_peak.custody_domain_id, h(51));
    }

    #[test]
    fn private_payment_intent_uses_one_time_key_and_replay_nullifier() {
        let key = Keypair::from_seed([12; 32]);
        let intent = PrivatePaymentIntent::issue(
            h(110),
            h(111),
            h(112),
            h(113),
            h(114),
            h(115),
            h(116),
            1_000,
            100,
            &key,
        )
        .unwrap();
        let mut registry = PaymentIntentRegistry::default();
        registry.register(intent.clone(), 99).unwrap();
        assert_eq!(
            registry.register(intent.clone(), 99),
            Err(WwmEconomicsError::DuplicateObject)
        );
        assert_eq!(
            intent.validate(100),
            Err(WwmEconomicsError::PaymentIntentExpired)
        );
    }

    #[test]
    fn role_bond_objective_fault_excludes_but_cannot_slash_before_gate() {
        let account = Keypair::from_seed([13; 32]);
        let bond = RoleBond::lock(
            BondRole::Executor,
            h(120),
            10_000,
            4_000,
            1_000,
            h(121),
            500,
            h(122),
            &account,
        )
        .unwrap();
        let mut ledger = BondLedger::default();
        ledger.credit_account(bond.account_key, 10_000).unwrap();
        let supply_before = ledger.account_balance(bond.account_key);
        ledger.register(bond.clone()).unwrap();
        let resolution = ledger
            .resolve(bond.bond_id, BondFinding::ObjectiveFault, 500)
            .unwrap();
        assert_eq!(resolution.slashed_amount, 0);
        assert_eq!(resolution.returned_amount, bond.amount);
        assert!(resolution.exclude_from_selection);
        assert_eq!(supply_before, 10_000);
        assert_eq!(ledger.account_balance(bond.account_key), 10_000);
        assert_eq!(ledger.held_total(), 0);
        assert!(!WWM_OBJECTIVE_SLASHING_ENABLED);
        assert!(!WWM_PROOFPOWER_ENABLED);
        assert!(!WWM_DUPLEX_ISSUANCE_ENABLED);
        assert_eq!(WWM_BASE_ISSUANCE, 0);
        assert_eq!(WWM_PROPOSAL_WEIGHT, 0);
        assert_eq!(WWM_FINALITY_WEIGHT, 0);
    }
    #[test]
    fn coverage_curve_clamps_before_u64_and_profile_aware_validation_rejects_bad_cache() {
        let profile = fund_profile(h(140));
        validate_fund_profile(&profile, true).unwrap();
        let policy = &profile.coverage_policy_rows.as_slice()[0];
        assert_eq!(funded_through_height(policy, 99).unwrap(), None);
        assert_eq!(funded_through_height(policy, 100).unwrap(), Some(10));
        assert_eq!(funded_through_height(policy, 109).unwrap(), Some(10));
        assert_eq!(funded_through_height(policy, 110).unwrap(), Some(11));
        assert_eq!(
            funded_through_height(policy, u128::MAX).unwrap(),
            Some(1_000)
        );
        assert_eq!(required_free_at(policy, 15).unwrap(), 150);

        let mut bad_profile = profile.clone();
        let mut policies = bad_profile.coverage_policy_rows.as_slice().to_vec();
        policies[0].baseline_liability_at_origin = u128::MAX;
        policies[0].liability_rate_per_height = 1;
        bad_profile.coverage_policy_rows = BoundedList::new(policies).unwrap();
        assert_eq!(
            validate_fund_profile(&bad_profile, true),
            Err(WwmEconomicsError::InvalidFundProfile)
        );

        let mut ledger = genesis_fund_ledger(&profile).unwrap();
        let mut rows = ledger.rows.as_slice().to_vec();
        rows[0].deposits = 100;
        rows[0].free = 100;
        rows[0].funded_through_height = OptionalU64(None);
        ledger.rows = BoundedList::new(rows).unwrap();
        assert!(ledger.validate());
        assert_eq!(
            validate_fund_ledger(&profile, &ledger),
            Err(WwmEconomicsError::InvalidFundLedger)
        );
    }

    #[test]
    fn permit_replay_multirow_atomicity_conservation_and_successor_lifecycle() {
        let profile_id = h(140);
        let successor_id = h(141);
        let payer_a = h(142);
        let payer_b = h(143);
        let mut state = FundAccountingState::new(h(144), h(145)).unwrap();
        state
            .install_genesis(fund_profile(profile_id), true)
            .unwrap();
        assert_eq!(state.current_profile_id(), profile_id);
        assert_eq!(state.wwm_held_total(), 0);
        assert!(state
            .view(profile_id, 10, 10)
            .unwrap()
            .rows
            .iter()
            .all(|row| row.ledger.funded_through_height.0.is_none()));
        state.credit_account(payer_a, 20_000).unwrap();
        state.credit_account(payer_b, 20_000).unwrap();

        let first = topup_permit(&state, payer_a, profile_id, FundBucketTag::Job, 151);
        let independent = topup_permit(
            &state,
            payer_b,
            profile_id,
            FundBucketTag::CustodyRetention,
            151,
        );
        state.top_up(&independent, 10, |_| true).unwrap();
        state.top_up(&first, 10, |_| true).unwrap();
        assert_eq!(
            state.top_up(&first, 10, |_| true),
            Err(WwmEconomicsError::InvalidFundPermit)
        );
        for bucket in [
            FundBucketTag::Repair,
            FundBucketTag::ChallengeReferee,
            FundBucketTag::Sponsor,
        ] {
            let permit = topup_permit(&state, payer_a, profile_id, bucket, 151);
            state.top_up(&permit, 10, |_| true).unwrap();
        }
        assert_eq!(state.wwm_held_total(), 755);
        assert_eq!(
            snapshot_rebuild_held_total(&state.snapshot().ledgers).unwrap(),
            state.wwm_held_total()
        );

        let requests = [
            ReservationRequest {
                obligation_id: h(150),
                kind: ObligationKind::Job,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
            ReservationRequest {
                obligation_id: h(151),
                kind: ObligationKind::CustodyRetention,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
            ReservationRequest {
                obligation_id: h(152),
                kind: ObligationKind::Repair,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
            ReservationRequest {
                obligation_id: h(153),
                kind: ObligationKind::ChallengeReferee,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
            ReservationRequest {
                obligation_id: h(154),
                kind: ObligationKind::Sponsor,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
        ];
        let obligations = state.reserve_many(profile_id, 10, &requests).unwrap();
        assert_eq!(obligations.len(), FUND_BUCKET_COUNT);
        assert!(state.ledger(profile_id).unwrap().rows.iter().all(|row| {
            row.free == 150
                && row.reserved == 1
                && row.live_liability == 1
                && row.funded_through_height.0 == Some(15)
        }));

        state
            .settle_obligation(profile_id, h(150), 1, 0, 0)
            .unwrap();
        for obligation_id in [h(151), h(152), h(153), h(154)] {
            state
                .settle_obligation(profile_id, obligation_id, 0, 0, 1)
                .unwrap();
        }
        assert_eq!(
            state.settle_obligation(profile_id, h(150), 1, 0, 0),
            Err(WwmEconomicsError::ObligationAlreadyConsumed)
        );

        state
            .stage_profile(fund_profile(successor_id), true)
            .unwrap();
        prefund_all_rows(&mut state, payer_b, successor_id, 150);
        let activation = state
            .lock_mutation(
                FundMutationOperation::Activate,
                profile_id,
                successor_id,
                h(155),
                10,
                11,
                1,
                vec![3; 64],
            )
            .unwrap();
        assert!(state
            .ledger(profile_id)
            .unwrap()
            .lock_ref
            .0
            .as_ref()
            .is_some_and(|reference| reference.lock_id == activation.lock_id));
        state.activate_successor(h(155), 10).unwrap();
        assert_eq!(state.current_profile_id(), successor_id);
        assert_eq!(
            state.ledger(profile_id).unwrap().status,
            FundLedgerStatus::Superseded
        );
        let closing = state
            .lock_mutation(
                FundMutationOperation::Close,
                profile_id,
                successor_id,
                h(156),
                11,
                12,
                1,
                vec![4; 64],
            )
            .unwrap();
        state.close_profile(closing.lock_id, 11).unwrap();
        assert_eq!(
            state.ledger(profile_id).unwrap().status,
            FundLedgerStatus::Closed
        );
        assert!(state
            .ledger(profile_id)
            .unwrap()
            .rows
            .iter()
            .all(|row| row.free == 0 && row.reserved == 0));
        assert_eq!(
            snapshot_rebuild_held_total(&state.snapshot().ledgers).unwrap(),
            state.wwm_held_total()
        );
        assert_eq!(WWM_BASE_ISSUANCE, 0);
        assert_eq!(WWM_PROPOSAL_WEIGHT, 0);
        assert_eq!(WWM_FINALITY_WEIGHT, 0);
    }

    #[test]
    fn one_less_multirow_reservation_rolls_back_every_row_and_snapshot_reorg_is_exact() {
        let profile_id = h(160);
        let payer = h(161);
        let mut state = FundAccountingState::new(h(162), h(163)).unwrap();
        state
            .install_genesis(fund_profile(profile_id), true)
            .unwrap();
        state.credit_account(payer, 1_000).unwrap();
        let job_permit = topup_permit(&state, payer, profile_id, FundBucketTag::Job, 150);
        state.top_up(&job_permit, 10, |_| true).unwrap();
        let custody_permit = topup_permit(
            &state,
            payer,
            profile_id,
            FundBucketTag::CustodyRetention,
            151,
        );
        state.top_up(&custody_permit, 10, |_| true).unwrap();
        let before = state.snapshot();
        let requests = [
            ReservationRequest {
                obligation_id: h(164),
                kind: ObligationKind::Job,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
            ReservationRequest {
                obligation_id: h(165),
                kind: ObligationKind::CustodyRetention,
                amount: 1,
                expected_prior_settlement_index: 1,
            },
        ];
        assert_eq!(
            state.reserve_many(profile_id, 10, &requests),
            Err(WwmEconomicsError::ReservationAdmissionFailed)
        );
        assert_eq!(state.snapshot(), before);

        let single = [ReservationRequest {
            obligation_id: h(166),
            kind: ObligationKind::CustodyRetention,
            amount: 1,
            expected_prior_settlement_index: 1,
        }];
        state.reserve_many(profile_id, 10, &single).unwrap();
        assert_ne!(state.snapshot(), before);
        state.restore_snapshot(before.clone()).unwrap();
        assert_eq!(state.snapshot(), before);
        let mut corrupt = before;
        corrupt.wwm_held_total += 1;
        assert_eq!(
            state.restore_snapshot(corrupt),
            Err(WwmEconomicsError::InvalidFundLedger)
        );
    }

    #[test]
    fn mutation_lock_expires_without_root_cycle_or_balance_change() {
        let current_id = h(170);
        let staged_id = h(171);
        let payer = h(172);
        let mut state = FundAccountingState::new(h(173), h(174)).unwrap();
        state
            .install_genesis(fund_profile(current_id), true)
            .unwrap();
        state.stage_profile(fund_profile(staged_id), true).unwrap();
        state.credit_account(payer, 1_000).unwrap();
        prefund_all_rows(&mut state, payer, staged_id, 150);
        let held = state.wwm_held_total();
        let lock = state
            .lock_mutation(
                FundMutationOperation::Activate,
                current_id,
                staged_id,
                h(175),
                10,
                11,
                1,
                vec![5; 64],
            )
            .unwrap();
        let reference = state
            .ledger(current_id)
            .unwrap()
            .lock_ref
            .0
            .as_ref()
            .unwrap();
        assert_eq!(reference.peer_profile_id, staged_id);
        assert!(reference.encode_canonical().len() < lock.encode_canonical().len());
        assert_ne!(lock.post_ref_root_0, [0; 32]);
        state.expire_lock(lock.lock_id, 11).unwrap();
        assert!(state.ledger(current_id).unwrap().lock_ref.0.is_none());
        assert!(state.ledger(staged_id).unwrap().lock_ref.0.is_none());
        assert_eq!(state.wwm_held_total(), held);
    }

    #[test]
    fn receipt_quorum_terminal_matrix_and_exactly_one_settlement() {
        let primary = ExecutorClaim {
            signer_id: h(180),
            control_cluster_id: h(181),
            ordered_token_ids_root: h(182),
            token_history_root: h(183),
            output_root: h(184),
        };
        let matching = ExecutorClaim {
            signer_id: h(185),
            control_cluster_id: h(186),
            ..primary
        };
        let dissenting = ExecutorClaim {
            signer_id: h(187),
            control_cluster_id: h(188),
            ordered_token_ids_root: h(189),
            token_history_root: h(190),
            output_root: h(191),
        };
        let matched = ReceiptOutcome::evaluate(
            RequestedEvidenceTier::MatchedQuorum,
            primary,
            &[matching, dissenting],
            false,
        )
        .unwrap();
        assert_eq!(matched.terminal_code, ReceiptTerminalCode::Success);
        assert_eq!(matched.matching_backup, Some(matching.signer_id));
        assert_eq!(matched.minority_disagreement, Some(dissenting.signer_id));
        let no_quorum = ReceiptOutcome::evaluate(
            RequestedEvidenceTier::MatchedQuorum,
            primary,
            &[
                ExecutorClaim {
                    signer_id: h(185),
                    control_cluster_id: h(186),
                    ordered_token_ids_root: h(192),
                    token_history_root: h(193),
                    output_root: h(194),
                },
                dissenting,
            ],
            true,
        )
        .unwrap();
        assert_eq!(no_quorum.terminal_code, ReceiptTerminalCode::NoQuorum);
        assert!(no_quorum.refundable());
        assert_eq!(
            ReceiptOutcome::evaluate(
                RequestedEvidenceTier::MatchedQuorum,
                primary,
                &[
                    ExecutorClaim {
                        signer_id: h(185),
                        control_cluster_id: h(186),
                        ordered_token_ids_root: h(192),
                        token_history_root: h(193),
                        output_root: h(194),
                    },
                    dissenting,
                ],
                false,
            ),
            Err(WwmEconomicsError::ReceiptNotTerminal)
        );

        let quote = quote(ResidencyCommitment::Resident);
        let mut settlements = SettlementBook::default();
        let terminal = settlements
            .record(
                h(195),
                no_quorum,
                &quote,
                bounds(),
                policy(),
                accounts(),
                h(196),
            )
            .unwrap();
        assert_eq!(terminal.paid, 0);
        assert_eq!(terminal.refund, quote.maximum_fee);
        assert_eq!(
            settlements.record(
                h(195),
                no_quorum,
                &quote,
                bounds(),
                policy(),
                accounts(),
                h(196),
            ),
            Err(WwmEconomicsError::SettlementAlreadyRecorded)
        );
    }

    #[test]
    fn sponsor_exhaustion_is_ring_fenced_and_resolution_releases_only_unused_sponsor_value() {
        let policy = SponsorPolicy {
            sponsor_id: h(200),
            sponsor_control_cluster: h(201),
            maximum_fee_per_job: 100,
            maximum_daily_spend: 100,
            maximum_daily_jobs: 1,
            maximum_total_spend: 100,
            policy_root: h(202),
        };
        let mut sponsors = SponsorBook::default();
        sponsors.prefund(policy, 100).unwrap();
        let reservation = sponsors
            .reserve(
                policy,
                h(203),
                100,
                1,
                FundingClassification::SelfDealing,
                h(204),
            )
            .unwrap();
        assert_eq!(reservation.production_credit, 0);
        assert_eq!(sponsors.balances(policy.sponsor_id), (0, 100));
        assert_eq!(
            sponsors.reserve(
                policy,
                h(205),
                1,
                2,
                FundingClassification::IndependentlyFunded,
                h(206),
            ),
            Err(WwmEconomicsError::SponsorNotPrefunded)
        );
        let resolution = sponsors.resolve(h(203), 60).unwrap();
        assert_eq!(resolution.spent, 60);
        assert_eq!(resolution.released, 40);
        assert_eq!(sponsors.balances(policy.sponsor_id), (40, 0));
        assert_eq!(
            sponsors.resolve(h(203), 60),
            Err(WwmEconomicsError::SponsorReservationAlreadyResolved)
        );
    }
}
