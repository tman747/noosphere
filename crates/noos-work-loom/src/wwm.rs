//! Application-funded World Wide Mind capacity quotes and settlement.
//!
//! All accounting in this module is bounded by user or sponsor escrow. It has
//! no issuance, proposal-weight, finality-weight, Proofpower, or validator
//! reward hook. Role bonds remain non-slashable until an objective-fault gate
//! demonstrates zero false slashes.

use crate::Hash32;
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub const BPS: u16 = 10_000;
pub const PILOT_MAX_CLUSTER_SHARE_BPS: u16 = 2_500;
pub const PILOT_MIN_EXECUTOR_CLUSTERS: usize = 5;
pub const PILOT_MIN_REGIONS: usize = 3;
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
    InvalidBond,
    UnknownBond,
    BondAlreadyResolved,
    InvalidPaymentIntent,
    PaymentIntentExpired,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityQuote {
    pub capsule_id: Hash32,
    pub numeric_profile_root: Hash32,
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
    pub production_credit: u128,
    pub reservation_id: Hash32,
}

#[derive(Debug, Default)]
pub struct SponsorBook {
    reservations: BTreeMap<Hash32, SponsorReservation>,
    daily_usage: BTreeMap<(Hash32, u64), (u128, u32)>,
    total_usage: BTreeMap<Hash32, u128>,
}

impl SponsorBook {
    pub fn reserve(
        &mut self,
        policy: SponsorPolicy,
        job_id: Hash32,
        amount: u128,
        day: u64,
        funding_classification: FundingClassification,
    ) -> Result<SponsorReservation, WwmEconomicsError> {
        policy.validate()?;
        if job_id == [0; 32] || amount == 0 || amount > policy.maximum_fee_per_job {
            return Err(WwmEconomicsError::SponsorCapExceeded);
        }
        if self.reservations.contains_key(&job_id) {
            return Err(WwmEconomicsError::DuplicateObject);
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
        let production_credit = 0;
        let reservation_id = digest(
            DomainId::WwmCapacityQuote,
            &[
                b"SPONSOR",
                &job_id,
                &policy.sponsor_id,
                &amount.to_le_bytes(),
                &day.to_le_bytes(),
                &[funding_classification as u8],
            ],
        )?;
        let reservation = SponsorReservation {
            job_id,
            sponsor_id: policy.sponsor_id,
            amount,
            day,
            funding_classification,
            production_credit,
            reservation_id,
        };
        self.daily_usage.insert(
            (policy.sponsor_id, day),
            (next_daily_spend, next_daily_jobs),
        );
        self.total_usage.insert(policy.sponsor_id, next_total);
        self.reservations.insert(job_id, reservation);
        Ok(reservation)
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBond {
    pub role: BondRole,
    pub account_key: Hash32,
    pub control_cluster: Hash32,
    pub amount: u128,
    pub policy_root: Hash32,
    pub locked_until_height: u64,
    pub nonce: Hash32,
    pub bond_id: Hash32,
    pub signature: [u8; 64],
}

impl RoleBond {
    pub fn lock(
        role: BondRole,
        control_cluster: Hash32,
        amount: u128,
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
            || self.locked_until_height == 0
        {
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
}

impl BondLedger {
    pub fn register(&mut self, bond: RoleBond) -> Result<(), WwmEconomicsError> {
        bond.validate()?;
        if self.bonds.contains_key(&bond.bond_id) {
            return Err(WwmEconomicsError::DuplicateObject);
        }
        self.bonds.insert(bond.bond_id, bond);
        Ok(())
    }

    pub fn resolve(
        &mut self,
        bond_id: Hash32,
        finding: BondFinding,
    ) -> Result<BondResolution, WwmEconomicsError> {
        let bond = self
            .bonds
            .get(&bond_id)
            .ok_or(WwmEconomicsError::UnknownBond)?;
        if !self.resolved.insert(bond_id) {
            return Err(WwmEconomicsError::BondAlreadyResolved);
        }
        Ok(BondResolution {
            bond_id,
            finding,
            returned_amount: bond.amount,
            slashed_amount: 0,
            exclude_from_selection: finding == BondFinding::ObjectiveFault,
        })
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
    pub peaks: Vec<ConcentrationPeak>,
    pub pilot_gate_passed: bool,
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
        let clusters = allocations
            .iter()
            .map(|allocation| allocation.control_cluster)
            .collect::<BTreeSet<_>>();
        let regions = allocations
            .iter()
            .map(|allocation| allocation.region)
            .collect::<BTreeSet<_>>();
        let pilot_gate_passed = clusters.len() >= PILOT_MIN_EXECUTOR_CLUSTERS
            && regions.len() >= PILOT_MIN_REGIONS
            && peaks.iter().all(|peak| {
                peak.selection_share_bps <= PILOT_MAX_CLUSTER_SHARE_BPS
                    && peak.custody_share_bps <= PILOT_MAX_CLUSTER_SHARE_BPS
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
            encoded.extend(allocation.selection_weight.to_le_bytes());
            encoded.extend(allocation.custody_bytes.to_le_bytes());
        }
        Ok(Self {
            allocation_root: digest(DomainId::WwmCapacityQuote, &[b"CONCENTRATION", &encoded])?,
            independent_control_clusters: clusters.len(),
            independent_regions: regions.len(),
            peaks,
            pilot_gate_passed,
        })
    }
}

fn failure_domain_id(allocation: CapacityAllocation, kind: FailureDomainKind) -> Hash32 {
    match kind {
        FailureDomainKind::ControlCluster => allocation.control_cluster,
        FailureDomainKind::CloudAccount => allocation.cloud_account,
        FailureDomainKind::Asn => allocation.asn_root,
        FailureDomainKind::Region => allocation.region,
        FailureDomainKind::SoftwareLineage => allocation.software_lineage,
        FailureDomainKind::ModelPublisher => allocation.model_publisher,
    }
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
        let circular = book
            .reserve(
                policy,
                h(34),
                100,
                1,
                FundingClassification::CircularFunding,
            )
            .unwrap();
        assert_eq!(circular.production_credit, 0);
        book.reserve(
            policy,
            h(35),
            100,
            1,
            FundingClassification::IndependentlyFunded,
        )
        .unwrap();
        assert_eq!(
            book.reserve(
                policy,
                h(36),
                1,
                1,
                FundingClassification::IndependentlyFunded
            ),
            Err(WwmEconomicsError::SponsorCapExceeded)
        );
        assert!(!WWM_APPLICATION_CREDIT_ENABLED);
    }

    #[test]
    fn concentration_gate_requires_five_clusters_three_regions_and_no_peak_over_quarter() {
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
                selection_weight: 20,
                custody_bytes: 20,
            });
        }
        let report = ConcentrationReport::build(&balanced).unwrap();
        assert!(report.pilot_gate_passed);
        assert_eq!(report.independent_control_clusters, 5);
        assert_eq!(report.independent_regions, 5);

        balanced[0].selection_weight = 80;
        balanced[1].custody_bytes = 80;
        let concentrated = ConcentrationReport::build(&balanced).unwrap();
        assert!(!concentrated.pilot_gate_passed);
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
            h(121),
            500,
            h(122),
            &account,
        )
        .unwrap();
        let mut ledger = BondLedger::default();
        ledger.register(bond.clone()).unwrap();
        let resolution = ledger
            .resolve(bond.bond_id, BondFinding::ObjectiveFault)
            .unwrap();
        assert_eq!(resolution.slashed_amount, 0);
        assert_eq!(resolution.returned_amount, bond.amount);
        assert!(resolution.exclude_from_selection);
        assert!(!WWM_OBJECTIVE_SLASHING_ENABLED);
        assert!(!WWM_PROOFPOWER_ENABLED);
        assert!(!WWM_DUPLEX_ISSUANCE_ENABLED);
        assert_eq!(WWM_BASE_ISSUANCE, 0);
        assert_eq!(WWM_PROPOSAL_WEIGHT, 0);
        assert_eq!(WWM_FINALITY_WEIGHT, 0);
    }
}
