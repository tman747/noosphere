//! TEE-private prompt attestation and rollback boundary for `N-TEE-FIBER` / `E-NEL-08`.
//!
//! This module verifies a complete tuple through a caller-supplied hardware quote verifier and
//! preserves `ASSURED_TEE` as a separate, non-orderable assurance class. The deterministic test
//! verifier exercises binding and state transitions only; it is not hardware/vendor evidence.

use noos_nel::{FinalityClass, PrivacyProfile as NelPrivacyProfile, PromptJob};
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

const ATTESTATION_DOMAIN: &[u8] = b"NOOS/UMBRA/TEE-FIBER-ATTESTATION/V1";
const JOB_DOMAIN: &str = "NOOS/UMBRA/TEE-FIBER/NEL-JOB/V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TeeAssurance {
    AssuredTee,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeePolicy {
    pub policy_root: Hash32,
    pub vendor_name: String,
    pub vendor_trust_root: Hash32,
    pub allowed_firmware_roots: BTreeSet<Hash32>,
    pub allowed_verifier_families: BTreeSet<Hash32>,
    pub executor_binary_root: Hash32,
    pub numeric_profile_root: Hash32,
    pub max_attestation_age: u64,
    pub max_request_length_delta: u64,
    pub max_response_length_delta: u64,
    pub max_duration_bucket_delta: u64,
    pub leakage_suite_root: Hash32,
    pub minimum_leakage_samples: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeeAttestation {
    pub job_id: Hash32,
    pub encrypted_prompt_commitment: Hash32,
    pub model_id: Hash32,
    pub decoding_profile_id: Hash32,
    pub numeric_profile_root: Hash32,
    pub executor_identity: Hash32,
    pub executor_binary_root: Hash32,
    pub firmware_root: Hash32,
    pub vendor_trust_root: Hash32,
    pub policy_root: Hash32,
    pub output_commitment: Hash32,
    pub challenge: Hash32,
    pub challenge_issued_at: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub rollback_counter: u64,
    pub quote: Vec<u8>,
}

impl TeeAttestation {
    pub fn report_data(&self) -> Result<Hash32, TeeError> {
        let mut encoded = ATTESTATION_DOMAIN.to_vec();
        for field in [
            self.job_id,
            self.encrypted_prompt_commitment,
            self.model_id,
            self.decoding_profile_id,
            self.numeric_profile_root,
            self.executor_identity,
            self.executor_binary_root,
            self.firmware_root,
            self.vendor_trust_root,
            self.policy_root,
            self.output_commitment,
            self.challenge,
        ] {
            encoded.extend_from_slice(&field);
        }
        for value in [
            self.challenge_issued_at,
            self.issued_at,
            self.expires_at,
            self.rollback_counter,
        ] {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
        if self.quote.is_empty() {
            return Err(TeeError::QuoteMissing);
        }
        Ok(*blake3::hash(&encoded).as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHardwareQuote {
    pub vendor_trust_root: Hash32,
    pub firmware_root: Hash32,
    pub executor_binary_root: Hash32,
    pub executor_identity: Hash32,
    pub rollback_counter: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteVerificationError;

pub trait HardwareQuoteVerifier {
    /// Stable family selected by the trusted host registry. It is not parsed from quote output.
    fn family_id(&self) -> Hash32;
    fn verify_quote(
        &self,
        quote: &[u8],
        expected_report_data: Hash32,
    ) -> Result<VerifiedHardwareQuote, QuoteVerificationError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeeReceipt {
    pub job_id: Hash32,
    pub prompt_commitment: Hash32,
    pub model_id: Hash32,
    pub output_commitment: Hash32,
    pub vendor_name: String,
    pub vendor_trust_root: Hash32,
    pub verifier_family: Hash32,
    pub firmware_root: Hash32,
    pub executor_binary_root: Hash32,
    pub policy_root: Hash32,
    pub attestation_commitment: Hash32,
    pub assurance: TeeAssurance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementRequirement {
    TeeVendor { vendor_trust_root: Hash32 },
    Nel(FinalityClass),
}

impl TeeReceipt {
    pub fn authorize(&self, requirement: SettlementRequirement) -> Result<(), TeeError> {
        match requirement {
            SettlementRequirement::TeeVendor { vendor_trust_root }
                if vendor_trust_root == self.vendor_trust_root =>
            {
                Ok(())
            }
            SettlementRequirement::TeeVendor { .. } => Err(TeeError::VendorPolicy),
            SettlementRequirement::Nel(_) => Err(TeeError::CrossClassSettlement),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeeError {
    ProfileDisabled,
    AlreadyDisabled,
    WrongNelProfile,
    TupleMismatch,
    QuoteMissing,
    QuoteInvalid,
    VendorPolicy,
    FirmwarePolicy,
    BinaryPolicy,
    StaleAttestation,
    ChallengeMismatch,
    ChallengeReplay,
    JobReplay,
    Rollback,
    CrossClassSettlement,
    LeakageBudgetExceeded,
    LeakageExperimentInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeakageSample {
    pub leakage_suite_root: Hash32,
    pub trial_index: u64,
    pub secret_prompt_commitment: Hash32,
    pub public_behavior_commitment: Hash32,
    pub request_ciphertext_bytes: u64,
    pub response_ciphertext_bytes: u64,
    /// A preregistered coarse class, not a wall-clock claim.
    pub duration_bucket: u64,
}

fn delta(values: impl Iterator<Item = u64>) -> u64 {
    let mut minimum = u64::MAX;
    let mut maximum = 0u64;
    let mut count = 0u64;
    for value in values {
        minimum = minimum.min(value);
        maximum = maximum.max(value);
        count = count.saturating_add(1);
    }
    if count == 0 {
        0
    } else {
        maximum.saturating_sub(minimum)
    }
}

pub fn verify_leakage_budget(
    samples: &[LeakageSample],
    policy: &TeePolicy,
) -> Result<(), TeeError> {
    let first = samples.first().ok_or(TeeError::LeakageExperimentInvalid)?;
    if policy.leakage_suite_root == [0; 32]
        || policy.minimum_leakage_samples < 2
        || samples.len() < policy.minimum_leakage_samples
        || samples.iter().any(|sample| {
            sample.leakage_suite_root != policy.leakage_suite_root
                || sample.public_behavior_commitment != first.public_behavior_commitment
        })
        || samples
            .iter()
            .map(|sample| sample.secret_prompt_commitment)
            .collect::<BTreeSet<_>>()
            .len()
            != samples.len()
        || samples
            .iter()
            .map(|sample| sample.trial_index)
            .collect::<BTreeSet<_>>()
            .len()
            != samples.len()
    {
        return Err(TeeError::LeakageExperimentInvalid);
    }
    if delta(samples.iter().map(|sample| sample.request_ciphertext_bytes))
        > policy.max_request_length_delta
        || delta(
            samples
                .iter()
                .map(|sample| sample.response_ciphertext_bytes),
        ) > policy.max_response_length_delta
        || delta(samples.iter().map(|sample| sample.duration_bucket))
            > policy.max_duration_bucket_delta
    {
        return Err(TeeError::LeakageBudgetExceeded);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackDisposition {
    PublicOrOffchain,
    WaitForPrivateProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRollback {
    pub disabled_at: u64,
    pub reason_commitment: Hash32,
    pub disposition: RollbackDisposition,
}

#[derive(Clone, Debug, Default)]
pub struct TeeFiberRegistry {
    active_policy: Option<TeePolicy>,
    rollback: Option<ProfileRollback>,
    seen_challenges: BTreeSet<Hash32>,
    high_counters: BTreeMap<Hash32, u64>,
    historical: BTreeMap<Hash32, TeeReceipt>,
}

impl TeeFiberRegistry {
    pub fn activate_local_precursor(&mut self, policy: TeePolicy) -> Result<(), TeeError> {
        if self.rollback.is_some() {
            return Err(TeeError::ProfileDisabled);
        }
        if policy.policy_root == [0; 32]
            || policy.vendor_name.is_empty()
            || policy.vendor_trust_root == [0; 32]
            || policy.allowed_firmware_roots.is_empty()
            || policy.allowed_verifier_families.is_empty()
            || policy.executor_binary_root == [0; 32]
            || policy.numeric_profile_root == [0; 32]
            || policy.max_attestation_age == 0
            || policy.leakage_suite_root == [0; 32]
            || policy.minimum_leakage_samples < 2
        {
            return Err(TeeError::VendorPolicy);
        }
        self.active_policy = Some(policy);
        self.rollback = None;
        Ok(())
    }

    pub fn disable_private_profile(
        &mut self,
        disabled_at: u64,
        reason_commitment: Hash32,
        disposition: RollbackDisposition,
    ) -> Result<(), TeeError> {
        if self.rollback.is_some() {
            return Err(TeeError::AlreadyDisabled);
        }
        if reason_commitment == [0; 32] {
            return Err(TeeError::TupleMismatch);
        }
        self.active_policy = None;
        self.rollback = Some(ProfileRollback {
            disabled_at,
            reason_commitment,
            disposition,
        });
        Ok(())
    }

    #[must_use]
    pub fn rollback(&self) -> Option<&ProfileRollback> {
        self.rollback.as_ref()
    }

    #[must_use]
    pub fn historical_receipt(&self, job_id: Hash32) -> Option<&TeeReceipt> {
        self.historical.get(&job_id)
    }

    pub fn verify_and_record(
        &mut self,
        job: &PromptJob,
        attestation: &TeeAttestation,
        expected_challenge: Hash32,
        now: u64,
        verifier: &dyn HardwareQuoteVerifier,
    ) -> Result<TeeReceipt, TeeError> {
        let policy = self
            .active_policy
            .as_ref()
            .ok_or(TeeError::ProfileDisabled)?;
        if job.privacy_profile != NelPrivacyProfile::P1Attested {
            return Err(TeeError::WrongNelProfile);
        }
        let job_id = noos_nel::domain_hash(JOB_DOMAIN, &job.encode());
        if attestation.job_id != job_id
            || attestation.encrypted_prompt_commitment != job.prompt_commitment
            || attestation.model_id != job.model_id
            || attestation.decoding_profile_id != job.decoding_profile_id
            || attestation.numeric_profile_root != policy.numeric_profile_root
            || attestation.policy_root != policy.policy_root
            || attestation.output_commitment == [0; 32]
        {
            return Err(TeeError::TupleMismatch);
        }
        if self.historical.contains_key(&job_id) {
            return Err(TeeError::JobReplay);
        }
        if attestation.challenge != expected_challenge {
            return Err(TeeError::ChallengeMismatch);
        }
        let challenge_key = attestation.challenge;
        if self.seen_challenges.contains(&challenge_key) {
            return Err(TeeError::ChallengeReplay);
        }
        let latest_allowed = attestation
            .challenge_issued_at
            .checked_add(policy.max_attestation_age)
            .ok_or(TeeError::StaleAttestation)?;
        if attestation.challenge_issued_at > attestation.issued_at
            || attestation.issued_at > now
            || now > attestation.expires_at
            || attestation.expires_at > latest_allowed
        {
            return Err(TeeError::StaleAttestation);
        }
        let verifier_family = verifier.family_id();
        if verifier_family == [0; 32]
            || !policy
                .allowed_verifier_families
                .contains(&verifier_family)
        {
            return Err(TeeError::VendorPolicy);
        }
        let report_data = attestation.report_data()?;
        let quote = verifier
            .verify_quote(&attestation.quote, report_data)
            .map_err(|_| TeeError::QuoteInvalid)?;
        if quote.vendor_trust_root != attestation.vendor_trust_root
            || quote.firmware_root != attestation.firmware_root
            || quote.executor_binary_root != attestation.executor_binary_root
            || quote.executor_identity != attestation.executor_identity
            || quote.rollback_counter != attestation.rollback_counter
        {
            return Err(TeeError::QuoteInvalid);
        }
        if quote.vendor_trust_root != policy.vendor_trust_root {
            return Err(TeeError::VendorPolicy);
        }
        if !policy.allowed_firmware_roots.contains(&quote.firmware_root) {
            return Err(TeeError::FirmwarePolicy);
        }
        if quote.executor_binary_root != policy.executor_binary_root {
            return Err(TeeError::BinaryPolicy);
        }
        if self
            .high_counters
            .get(&quote.executor_identity)
            .is_some_and(|previous| quote.rollback_counter <= *previous)
        {
            return Err(TeeError::Rollback);
        }
        let mut encoded = ATTESTATION_DOMAIN.to_vec();
        encoded.extend_from_slice(&report_data);
        encoded.extend_from_slice(&verifier_family);
        let receipt = TeeReceipt {
            job_id,
            prompt_commitment: job.prompt_commitment,
            model_id: job.model_id,
            output_commitment: attestation.output_commitment,
            vendor_name: policy.vendor_name.clone(),
            vendor_trust_root: policy.vendor_trust_root,
            verifier_family,
            firmware_root: attestation.firmware_root,
            executor_binary_root: attestation.executor_binary_root,
            policy_root: policy.policy_root,
            attestation_commitment: *blake3::hash(&encoded).as_bytes(),
            assurance: TeeAssurance::AssuredTee,
        };
        self.seen_challenges.insert(challenge_key);
        self.high_counters
            .insert(quote.executor_identity, quote.rollback_counter);
        self.historical.insert(job_id, receipt.clone());
        Ok(receipt)
    }
}

/// Explicitly wipeable prompt buffer. This tests lifecycle state; it does not claim compiler- or
/// hardware-guaranteed erasure outside this process.
#[derive(Debug)]
pub struct PromptSecretBuffer {
    bytes: Vec<u8>,
    zeroized: bool,
}

impl PromptSecretBuffer {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            zeroized: false,
        }
    }

    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NOOS/UMBRA/TEE-PROMPT-COMMITMENT/V1");
        hasher.update(&self.bytes);
        *hasher.finalize().as_bytes()
    }

    pub fn zeroize(&mut self) {
        self.bytes.fill(0);
        self.zeroized = true;
    }

    #[must_use]
    pub fn is_zeroized(&self) -> bool {
        self.zeroized && self.bytes.iter().all(|byte| *byte == 0)
    }
}

impl Drop for PromptSecretBuffer {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.zeroized = true;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn job(prompt: u8, model: u8) -> PromptJob {
        PromptJob {
            model_id: h(model),
            prompt_commitment: h(prompt),
            prompt_blob_ref: h(3),
            privacy_profile: NelPrivacyProfile::P1Attested,
            decoding_profile_id: h(4),
            max_new_tokens: 8,
            fee_escrow: 10,
            committee_size: 1,
            quorum: 1,
            bond_class: 1,
            challenge_period: 10,
        }
    }

    fn policy() -> TeePolicy {
        TeePolicy {
            policy_root: h(10),
            vendor_name: "named-fixture-vendor-not-production".into(),
            vendor_trust_root: h(11),
            allowed_firmware_roots: BTreeSet::from([h(12)]),
            allowed_verifier_families: BTreeSet::from([h(99)]),
            executor_binary_root: h(13),
            numeric_profile_root: h(14),
            max_attestation_age: 20,
            max_request_length_delta: 0,
            max_response_length_delta: 0,
            max_duration_bucket_delta: 0,
            leakage_suite_root: h(17),
            minimum_leakage_samples: 2,
        }
    }

    fn attestation(job: &PromptJob, challenge: u8, counter: u64) -> TeeAttestation {
        let mut statement = TeeAttestation {
            job_id: noos_nel::domain_hash(JOB_DOMAIN, &job.encode()),
            encrypted_prompt_commitment: job.prompt_commitment,
            model_id: job.model_id,
            decoding_profile_id: job.decoding_profile_id,
            numeric_profile_root: h(14),
            executor_identity: h(15),
            executor_binary_root: h(13),
            firmware_root: h(12),
            vendor_trust_root: h(11),
            policy_root: h(10),
            output_commitment: h(16),
            challenge: h(challenge),
            challenge_issued_at: 100,
            issued_at: 101,
            expires_at: 120,
            rollback_counter: counter,
            quote: vec![1],
        };
        statement.quote = statement.report_data().unwrap().to_vec();
        statement
    }

    struct FixtureQuoteVerifier;
    impl HardwareQuoteVerifier for FixtureQuoteVerifier {
        fn family_id(&self) -> Hash32 {
            h(99)
        }
        fn verify_quote(
            &self,
            quote: &[u8],
            expected_report_data: Hash32,
        ) -> Result<VerifiedHardwareQuote, QuoteVerificationError> {
            if quote != expected_report_data {
                return Err(QuoteVerificationError);
            }
            Ok(VerifiedHardwareQuote {
                vendor_trust_root: h(11),
                firmware_root: h(12),
                executor_binary_root: h(13),
                executor_identity: h(15),
                rollback_counter: 1,
            })
        }
    }

    struct CounterVerifier(u64);
    impl HardwareQuoteVerifier for CounterVerifier {
        fn family_id(&self) -> Hash32 {
            h(99)
        }
        fn verify_quote(
            &self,
            quote: &[u8],
            expected_report_data: Hash32,
        ) -> Result<VerifiedHardwareQuote, QuoteVerificationError> {
            if quote != expected_report_data {
                return Err(QuoteVerificationError);
            }
            Ok(VerifiedHardwareQuote {
                vendor_trust_root: h(11),
                firmware_root: h(12),
                executor_binary_root: h(13),
                executor_identity: h(15),
                rollback_counter: self.0,
            })
        }
    }

    struct FirmwareDowngradeVerifier;
    impl HardwareQuoteVerifier for FirmwareDowngradeVerifier {
        fn family_id(&self) -> Hash32 {
            h(99)
        }
        fn verify_quote(
            &self,
            quote: &[u8],
            expected_report_data: Hash32,
        ) -> Result<VerifiedHardwareQuote, QuoteVerificationError> {
            if quote != expected_report_data {
                return Err(QuoteVerificationError);
            }
            Ok(VerifiedHardwareQuote {
                vendor_trust_root: h(11),
                firmware_root: h(77),
                executor_binary_root: h(13),
                executor_identity: h(15),
                rollback_counter: 2,
            })
        }
    }

    struct UnregisteredVerifierFamily;
    impl HardwareQuoteVerifier for UnregisteredVerifierFamily {
        fn family_id(&self) -> Hash32 {
            h(98)
        }
        fn verify_quote(
            &self,
            quote: &[u8],
            expected_report_data: Hash32,
        ) -> Result<VerifiedHardwareQuote, QuoteVerificationError> {
            if quote != expected_report_data {
                return Err(QuoteVerificationError);
            }
            Ok(VerifiedHardwareQuote {
                vendor_trust_root: h(11),
                firmware_root: h(12),
                executor_binary_root: h(13),
                executor_identity: h(15),
                rollback_counter: 1,
            })
        }
    }

    #[test]
    fn complete_attestation_binds_nel_job_and_names_vendor_trust() {
        let job = job(1, 2);
        let statement = attestation(&job, 20, 1);
        let mut registry = TeeFiberRegistry::default();
        registry.activate_local_precursor(policy()).unwrap();
        let receipt = registry
            .verify_and_record(&job, &statement, h(20), 110, &FixtureQuoteVerifier)
            .unwrap();
        assert_eq!(receipt.assurance, TeeAssurance::AssuredTee);
        assert!(receipt.vendor_name.contains("not-production"));
        assert_eq!(receipt.verifier_family, h(99));
        assert_eq!(
            receipt.authorize(SettlementRequirement::TeeVendor {
                vendor_trust_root: h(11)
            }),
            Ok(())
        );
    }
    #[test]
    fn unregistered_quote_verifier_family_rejects() {
        let untrusted_job = job(2, 2);
        let untrusted = attestation(&untrusted_job, 21, 1);
        let mut untrusted_registry = TeeFiberRegistry::default();
        untrusted_registry.activate_local_precursor(policy()).unwrap();
        assert_eq!(
            untrusted_registry.verify_and_record(
                &untrusted_job,
                &untrusted,
                h(21),
                110,
                &UnregisteredVerifierFamily
            ),
            Err(TeeError::VendorPolicy)
        );
    }

    #[test]
    fn every_tuple_field_mutation_and_cross_job_splice_rejects() {
        let original_job = job(1, 2);
        let original = attestation(&original_job, 20, 1);
        let mutations = vec![
            TeeAttestation {
                job_id: h(31),
                ..original.clone()
            },
            TeeAttestation {
                encrypted_prompt_commitment: h(31),
                ..original.clone()
            },
            TeeAttestation {
                model_id: h(31),
                ..original.clone()
            },
            TeeAttestation {
                decoding_profile_id: h(31),
                ..original.clone()
            },
            TeeAttestation {
                numeric_profile_root: h(31),
                ..original.clone()
            },
            TeeAttestation {
                executor_identity: h(31),
                ..original.clone()
            },
            TeeAttestation {
                executor_binary_root: h(31),
                ..original.clone()
            },
            TeeAttestation {
                firmware_root: h(31),
                ..original.clone()
            },
            TeeAttestation {
                vendor_trust_root: h(31),
                ..original.clone()
            },
            TeeAttestation {
                policy_root: h(31),
                ..original.clone()
            },
            TeeAttestation {
                output_commitment: h(31),
                ..original.clone()
            },
            TeeAttestation {
                challenge: h(31),
                ..original.clone()
            },
            TeeAttestation {
                challenge_issued_at: 99,
                ..original.clone()
            },
            TeeAttestation {
                issued_at: 102,
                ..original.clone()
            },
            TeeAttestation {
                expires_at: 119,
                ..original.clone()
            },
            TeeAttestation {
                rollback_counter: 2,
                ..original.clone()
            },
        ];
        for mutation in mutations {
            let mut registry = TeeFiberRegistry::default();
            registry.activate_local_precursor(policy()).unwrap();
            assert!(registry
                .verify_and_record(&original_job, &mutation, h(20), 110, &FixtureQuoteVerifier)
                .is_err());
        }
        let other_job = job(9, 2);
        let mut registry = TeeFiberRegistry::default();
        registry.activate_local_precursor(policy()).unwrap();
        assert_eq!(
            registry.verify_and_record(&other_job, &original, h(20), 110, &FixtureQuoteVerifier),
            Err(TeeError::TupleMismatch)
        );
    }

    #[test]
    fn replay_stale_firmware_downgrade_and_counter_rollback_reject() {
        let base_job = job(1, 2);
        let first = attestation(&base_job, 20, 1);
        let mut registry = TeeFiberRegistry::default();
        registry.activate_local_precursor(policy()).unwrap();
        registry
            .verify_and_record(&base_job, &first, h(20), 110, &FixtureQuoteVerifier)
            .unwrap();
        let relay_job = job(5, 2);
        let relay = attestation(&relay_job, 20, 2);
        assert_eq!(
            registry.verify_and_record(&relay_job, &relay, h(20), 110, &CounterVerifier(2)),
            Err(TeeError::ChallengeReplay)
        );
        assert_eq!(
            registry.verify_and_record(&base_job, &first, h(20), 110, &FixtureQuoteVerifier),
            Err(TeeError::JobReplay)
        );
        let same_job_new_challenge = attestation(&base_job, 24, 2);
        assert_eq!(
            registry.verify_and_record(
                &base_job,
                &same_job_new_challenge,
                h(24),
                110,
                &CounterVerifier(2)
            ),
            Err(TeeError::JobReplay)
        );

        let stale_job = job(2, 2);
        let mut stale = attestation(&stale_job, 21, 2);
        stale.expires_at = 105;
        stale.quote = stale.report_data().unwrap().to_vec();
        assert_eq!(
            registry.verify_and_record(&stale_job, &stale, h(21), 110, &CounterVerifier(2)),
            Err(TeeError::StaleAttestation)
        );

        let downgrade_job = job(3, 2);
        let mut downgraded = attestation(&downgrade_job, 22, 2);
        downgraded.firmware_root = h(77);
        downgraded.quote = downgraded.report_data().unwrap().to_vec();
        assert_eq!(
            registry.verify_and_record(
                &downgrade_job,
                &downgraded,
                h(22),
                110,
                &FirmwareDowngradeVerifier
            ),
            Err(TeeError::FirmwarePolicy)
        );

        let rollback_job = job(4, 2);
        let rollback = attestation(&rollback_job, 23, 1);
        assert_eq!(
            registry.verify_and_record(&rollback_job, &rollback, h(23), 110, &CounterVerifier(1)),
            Err(TeeError::Rollback)
        );
    }

    #[test]
    fn tee_result_never_spends_as_open_assurance_or_proof() {
        let job = job(1, 2);
        let statement = attestation(&job, 20, 1);
        let mut registry = TeeFiberRegistry::default();
        registry.activate_local_precursor(policy()).unwrap();
        let receipt = registry
            .verify_and_record(&job, &statement, h(20), 110, &FixtureQuoteVerifier)
            .unwrap();
        for class in [
            FinalityClass::Soft,
            FinalityClass::Anchored,
            FinalityClass::Assured,
            FinalityClass::Proven,
        ] {
            assert_eq!(
                receipt.authorize(SettlementRequirement::Nel(class)),
                Err(TeeError::CrossClassSettlement)
            );
        }
    }

    #[test]
    fn equal_public_behavior_leakage_budget_and_cross_job_prompt_separation() {
        let samples = [
            LeakageSample {
                leakage_suite_root: h(17),
                trial_index: 0,
                secret_prompt_commitment: h(1),
                public_behavior_commitment: h(8),
                request_ciphertext_bytes: 4096,
                response_ciphertext_bytes: 2048,
                duration_bucket: 4,
            },
            LeakageSample {
                leakage_suite_root: h(17),
                trial_index: 1,
                secret_prompt_commitment: h(2),
                public_behavior_commitment: h(8),
                request_ciphertext_bytes: 4096,
                response_ciphertext_bytes: 2048,
                duration_bucket: 4,
            },
        ];
        assert_eq!(verify_leakage_budget(&samples, &policy()), Ok(()));
        let mut leaked = samples.clone();
        leaked[1].request_ciphertext_bytes = 4097;
        assert_eq!(
            verify_leakage_budget(&leaked, &policy()),
            Err(TeeError::LeakageBudgetExceeded)
        );
        let mut wrong_suite = samples.clone();
        wrong_suite[1].leakage_suite_root = h(18);
        assert_eq!(
            verify_leakage_budget(&wrong_suite, &policy()),
            Err(TeeError::LeakageExperimentInvalid)
        );
        let mut duplicate_trial = samples.clone();
        duplicate_trial[1].trial_index = 0;
        assert_eq!(
            verify_leakage_budget(&duplicate_trial, &policy()),
            Err(TeeError::LeakageExperimentInvalid)
        );
        assert_ne!(
            noos_nel::domain_hash(JOB_DOMAIN, &job(1, 2).encode()),
            noos_nel::domain_hash(JOB_DOMAIN, &job(2, 2).encode())
        );
    }

    #[test]
    fn rollback_disables_only_new_private_jobs_and_preserves_history() {
        let job = job(1, 2);
        let statement = attestation(&job, 20, 1);
        let mut registry = TeeFiberRegistry::default();
        registry.activate_local_precursor(policy()).unwrap();
        let receipt = registry
            .verify_and_record(&job, &statement, h(20), 110, &FixtureQuoteVerifier)
            .unwrap();
        registry
            .disable_private_profile(111, h(55), RollbackDisposition::PublicOrOffchain)
            .unwrap();
        assert_eq!(registry.rollback().unwrap().disabled_at, 111);
        assert_eq!(
            registry.rollback().unwrap().disposition,
            RollbackDisposition::PublicOrOffchain
        );
        assert_eq!(registry.historical_receipt(receipt.job_id), Some(&receipt));
        let next = attestation(&job, 21, 2);
        assert_eq!(
            registry.verify_and_record(&job, &next, h(21), 112, &CounterVerifier(2)),
            Err(TeeError::ProfileDisabled)
        );
        assert_eq!(
            registry.activate_local_precursor(policy()),
            Err(TeeError::ProfileDisabled)
        );
        assert_eq!(
            registry.disable_private_profile(
                113,
                h(56),
                RollbackDisposition::WaitForPrivateProof
            ),
            Err(TeeError::AlreadyDisabled)
        );
    }

    #[test]
    fn prompt_secret_zeroization_state_is_explicit() {
        let mut prompt = PromptSecretBuffer::new(b"cross-job secret prompt".to_vec());
        assert!(!prompt.is_zeroized());
        assert_ne!(prompt.commitment(), [0; 32]);
        prompt.zeroize();
        assert!(prompt.is_zeroized());
    }
}
