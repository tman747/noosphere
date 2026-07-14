//! Replaceable public WWM gateway core.
//!
//! The gateway pins finalized state from independent read endpoints, issues
//! signed bounded quotes, enforces anonymous-credential rate limits and sponsor
//! caps, and exposes receipts without upgrading their actual NEL finality.
//! It stores prompt commitments only. Production activation remains disabled.

#![forbid(unsafe_code)]
pub mod service;

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use noos_nel::{FinalityClass, Hash32};
use std::collections::{BTreeMap, BTreeSet};

pub const MIN_STATE_ENDPOINTS: usize = 3;
pub const STATE_QUORUM: usize = 2;
pub const MAX_STATE_ENDPOINTS: usize = 16;
pub const MAX_GATEWAY_NODES: usize = 16;
pub const MAX_QUERY_TOKENS: u32 = 32_768;
pub const MAX_OUTPUT_TOKENS: u32 = 4_096;
pub const MAX_RECEIPT_SOURCES: usize = 256;
pub const WWM_PUBLIC_GATEWAY_ENABLED: bool = false;
pub const WWM_GATEWAY_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayError {
    InvalidObservation,
    InsufficientStateQuorum,
    SplitView,
    InvalidManifest,
    InvalidRequest,
    InvalidQuote,
    InvalidSignature,
    RateLimited,
    UnknownSponsor,
    SponsorExpired,
    SponsorPolicy,
    SponsorExhausted,
    QuoteExpired,
    DuplicateJob,
    UnknownJob,
    InvalidReceipt,
    FinalityOverstatement,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateObservation {
    pub endpoint_id: Hash32,
    pub control_cluster: Hash32,
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub finalized_height: u64,
    pub finalized_hash: Hash32,
    pub capsule_id: Hash32,
    pub query_policy_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub executor_registry_epoch: u64,
    pub fee_schedule_id: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StateTuple {
    chain_id: Hash32,
    genesis_hash: Hash32,
    finalized_height: u64,
    finalized_hash: Hash32,
    capsule_id: Hash32,
    query_policy_id: Hash32,
    knowledge_snapshot_id: Hash32,
    executor_registry_epoch: u64,
    fee_schedule_id: Hash32,
}

impl StateObservation {
    fn validate(&self) -> Result<(), GatewayError> {
        if self.endpoint_id == [0; 32]
            || self.control_cluster == [0; 32]
            || self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.finalized_height == 0
            || self.finalized_hash == [0; 32]
            || self.capsule_id == [0; 32]
            || self.query_policy_id == [0; 32]
            || self.knowledge_snapshot_id == [0; 32]
            || self.executor_registry_epoch == 0
            || self.fee_schedule_id == [0; 32]
        {
            return Err(GatewayError::InvalidObservation);
        }
        Ok(())
    }

    fn tuple(&self) -> StateTuple {
        StateTuple {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            finalized_height: self.finalized_height,
            finalized_hash: self.finalized_hash,
            capsule_id: self.capsule_id,
            query_policy_id: self.query_policy_id,
            knowledge_snapshot_id: self.knowledge_snapshot_id,
            executor_registry_epoch: self.executor_registry_epoch,
            fee_schedule_id: self.fee_schedule_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedState {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub finalized_height: u64,
    pub finalized_hash: Hash32,
    pub capsule_id: Hash32,
    pub query_policy_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub executor_registry_epoch: u64,
    pub fee_schedule_id: Hash32,
    pub agreeing_endpoints: Vec<Hash32>,
    pub agreeing_control_clusters: Vec<Hash32>,
    pub pin_id: Hash32,
}

pub fn pin_state(observations: &[StateObservation]) -> Result<PinnedState, GatewayError> {
    if observations.len() < MIN_STATE_ENDPOINTS || observations.len() > MAX_STATE_ENDPOINTS {
        return Err(GatewayError::InsufficientStateQuorum);
    }
    let mut endpoints = BTreeSet::new();
    let mut groups: BTreeMap<StateTuple, Vec<&StateObservation>> = BTreeMap::new();
    for observation in observations {
        observation.validate()?;
        if !endpoints.insert(observation.endpoint_id) {
            return Err(GatewayError::InvalidObservation);
        }
        groups
            .entry(observation.tuple())
            .or_default()
            .push(observation);
    }
    let mut eligible = groups
        .into_iter()
        .filter_map(|(state, members)| {
            let clusters = members
                .iter()
                .map(|member| member.control_cluster)
                .collect::<BTreeSet<_>>();
            (members.len() >= STATE_QUORUM && clusters.len() >= STATE_QUORUM)
                .then_some((state, members, clusters))
        })
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Err(GatewayError::InsufficientStateQuorum);
    }
    if eligible.len() != 1 {
        return Err(GatewayError::SplitView);
    }
    let (state, mut members, clusters) = eligible.remove(0);
    members.sort_by_key(|member| member.endpoint_id);
    let agreeing_endpoints = members
        .iter()
        .map(|member| member.endpoint_id)
        .collect::<Vec<_>>();
    let agreeing_control_clusters = clusters.into_iter().collect::<Vec<_>>();
    let body = encode_pin_body(&state, &agreeing_endpoints, &agreeing_control_clusters)?;
    let pin_id = digest(DomainId::WwmPublicQuote, &[b"STATE-PIN", &body])?;
    Ok(PinnedState {
        chain_id: state.chain_id,
        genesis_hash: state.genesis_hash,
        finalized_height: state.finalized_height,
        finalized_hash: state.finalized_hash,
        capsule_id: state.capsule_id,
        query_policy_id: state.query_policy_id,
        knowledge_snapshot_id: state.knowledge_snapshot_id,
        executor_registry_epoch: state.executor_registry_epoch,
        fee_schedule_id: state.fee_schedule_id,
        agreeing_endpoints,
        agreeing_control_clusters,
        pin_id,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayManifest {
    pub gateway_key: Hash32,
    pub state_endpoint_ids: Vec<Hash32>,
    pub state_control_clusters: Vec<Hash32>,
    pub api_version: u16,
    pub maximum_quote_lifetime_blocks: u32,
}

impl GatewayManifest {
    pub fn validate(&self) -> Result<(), GatewayError> {
        self.validate_with_minimums(MIN_STATE_ENDPOINTS, STATE_QUORUM)
    }

    /// Validate an explicitly local, test-only manifest.
    ///
    /// This does not satisfy the independent state-quorum requirement and must
    /// never be interpreted as WWM production activation.
    pub fn validate_test_only(&self) -> Result<(), GatewayError> {
        self.validate_with_minimums(1, 1)
    }

    fn validate_with_minimums(
        &self,
        minimum_endpoints: usize,
        minimum_clusters: usize,
    ) -> Result<(), GatewayError> {
        if self.gateway_key == [0; 32]
            || self.state_endpoint_ids.len() < minimum_endpoints
            || self.state_endpoint_ids.len() > MAX_GATEWAY_NODES
            || self.state_endpoint_ids.len() != self.state_control_clusters.len()
            || !strictly_sorted(&self.state_endpoint_ids)
            || self.state_endpoint_ids.contains(&[0; 32])
            || self.state_control_clusters.contains(&[0; 32])
            || self
                .state_control_clusters
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                < minimum_clusters
            || self.api_version != 1
            || self.maximum_quote_lifetime_blocks == 0
        {
            return Err(GatewayError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryBounds {
    pub input_tokens: u32,
    pub retrieved_context_tokens: u32,
    pub maximum_output_tokens: u32,
    pub requested_finality: FinalityClass,
}

impl QueryBounds {
    fn validate(self) -> Result<(), GatewayError> {
        let context = self
            .input_tokens
            .checked_add(self.retrieved_context_tokens)
            .ok_or(GatewayError::ArithmeticOverflow)?;
        if self.input_tokens == 0
            || context > MAX_QUERY_TOKENS
            || self.maximum_output_tokens == 0
            || self.maximum_output_tokens > MAX_OUTPUT_TOKENS
            || self.requested_finality == FinalityClass::Proven
        {
            return Err(GatewayError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSchedule {
    pub schedule_id: Hash32,
    pub base_micro_noos: u64,
    pub input_token_micro_noos: u64,
    pub retrieval_token_micro_noos: u64,
    pub output_token_micro_noos: u64,
    pub anchored_surcharge_micro_noos: u64,
    pub assured_surcharge_micro_noos: u64,
}

impl FeeSchedule {
    pub fn maximum_fee(self, bounds: QueryBounds) -> Result<u64, GatewayError> {
        bounds.validate()?;
        if self.schedule_id == [0; 32] {
            return Err(GatewayError::InvalidQuote);
        }
        let input = self
            .input_token_micro_noos
            .checked_mul(u64::from(bounds.input_tokens))
            .ok_or(GatewayError::ArithmeticOverflow)?;
        let retrieval = self
            .retrieval_token_micro_noos
            .checked_mul(u64::from(bounds.retrieved_context_tokens))
            .ok_or(GatewayError::ArithmeticOverflow)?;
        let output = self
            .output_token_micro_noos
            .checked_mul(u64::from(bounds.maximum_output_tokens))
            .ok_or(GatewayError::ArithmeticOverflow)?;
        let surcharge = match bounds.requested_finality {
            FinalityClass::Soft => 0,
            FinalityClass::Anchored => self.anchored_surcharge_micro_noos,
            FinalityClass::Assured => self.assured_surcharge_micro_noos,
            FinalityClass::Proven => return Err(GatewayError::InvalidRequest),
        };
        self.base_micro_noos
            .checked_add(input)
            .and_then(|value| value.checked_add(retrieval))
            .and_then(|value| value.checked_add(output))
            .and_then(|value| value.checked_add(surcharge))
            .ok_or(GatewayError::ArithmeticOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicQueryRequest {
    pub requester_credential: Hash32,
    pub prompt_commitment: Hash32,
    pub bounds: QueryBounds,
    pub sponsor_id: Option<Hash32>,
    pub client_nonce: Hash32,
}

impl PublicQueryRequest {
    fn validate(&self) -> Result<(), GatewayError> {
        self.bounds.validate()?;
        if self.requester_credential == [0; 32]
            || self.prompt_commitment == [0; 32]
            || self.client_nonce == [0; 32]
            || self.sponsor_id == Some([0; 32])
        {
            return Err(GatewayError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicQuote {
    pub gateway_key: Hash32,
    pub pin_id: Hash32,
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub capsule_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub query_policy_id: Hash32,
    pub fee_schedule_id: Hash32,
    pub executor_registry_epoch: u64,
    pub prompt_commitment: Hash32,
    pub client_nonce: Hash32,
    pub bounds: QueryBounds,
    pub sponsor_id: Option<Hash32>,
    pub maximum_fee_micro_noos: u64,
    pub expires_height: u64,
    pub quote_id: Hash32,
    pub signature: [u8; 64],
}

impl PublicQuote {
    pub fn validate(&self) -> Result<(), GatewayError> {
        let body = self.body()?;
        if self.quote_id == [0; 32] || digest(DomainId::WwmPublicQuote, &[&body])? != self.quote_id
        {
            return Err(GatewayError::InvalidQuote);
        }
        verify(
            self.gateway_key,
            DomainId::WwmPublicQuote,
            self.quote_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, GatewayError> {
        self.bounds.validate()?;
        if self.gateway_key == [0; 32]
            || self.pin_id == [0; 32]
            || self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.capsule_id == [0; 32]
            || self.knowledge_snapshot_id == [0; 32]
            || self.query_policy_id == [0; 32]
            || self.fee_schedule_id == [0; 32]
            || self.executor_registry_epoch == 0
            || self.prompt_commitment == [0; 32]
            || self.client_nonce == [0; 32]
            || self.maximum_fee_micro_noos == 0
            || self.expires_height == 0
        {
            return Err(GatewayError::InvalidQuote);
        }
        let mut body = Vec::with_capacity(340);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.gateway_key);
        body.extend(self.pin_id);
        body.extend(self.chain_id);
        body.extend(self.genesis_hash);
        body.extend(self.capsule_id);
        body.extend(self.knowledge_snapshot_id);
        body.extend(self.query_policy_id);
        body.extend(self.fee_schedule_id);
        body.extend(self.executor_registry_epoch.to_le_bytes());
        body.extend(self.prompt_commitment);
        body.extend(self.client_nonce);
        body.extend(self.bounds.input_tokens.to_le_bytes());
        body.extend(self.bounds.retrieved_context_tokens.to_le_bytes());
        body.extend(self.bounds.maximum_output_tokens.to_le_bytes());
        body.push(finality_code(self.bounds.requested_finality)?);
        match self.sponsor_id {
            Some(id) => {
                body.push(1);
                body.extend(id);
            }
            None => body.push(0),
        }
        body.extend(self.maximum_fee_micro_noos.to_le_bytes());
        body.extend(self.expires_height.to_le_bytes());
        Ok(body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatePolicy {
    pub window_blocks: u64,
    pub maximum_requests: u32,
    pub maximum_output_tokens: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateUsage {
    window_start: u64,
    requests: u32,
    output_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorAccount {
    pub sponsor_id: Hash32,
    pub remaining_micro_noos: u64,
    pub per_job_cap_micro_noos: u64,
    pub allowed_capsule_id: Option<Hash32>,
    pub expires_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayJob {
    pub job_id: Hash32,
    pub quote_id: Hash32,
    pub prompt_commitment: Hash32,
    pub capsule_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub requested_finality: FinalityClass,
    pub escrow_micro_noos: u64,
    pub sponsor_id: Option<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptView {
    pub gateway_key: Hash32,
    pub job_id: Hash32,
    pub quote_id: Hash32,
    pub capsule_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub token_history_root: Hash32,
    pub retrieval_receipt_id: Option<Hash32>,
    pub source_mindlink_ids: Vec<Hash32>,
    pub actual_finality: FinalityClass,
    pub assurance_label: &'static str,
    pub settlement_id: Hash32,
    pub charged_micro_noos: u64,
    pub refunded_micro_noos: u64,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl ReceiptView {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.gateway_key == [0; 32]
            || self.job_id == [0; 32]
            || self.quote_id == [0; 32]
            || self.capsule_id == [0; 32]
            || self.knowledge_snapshot_id == [0; 32]
            || self.token_history_root == [0; 32]
            || self.retrieval_receipt_id == Some([0; 32])
            || self.source_mindlink_ids.len() > MAX_RECEIPT_SOURCES
            || !strictly_sorted(&self.source_mindlink_ids)
            || self.source_mindlink_ids.contains(&[0; 32])
            || self.assurance_label != assurance_label(self.actual_finality)
            || self.settlement_id == [0; 32]
            || self.receipt_id == [0; 32]
        {
            return Err(GatewayError::InvalidReceipt);
        }
        let body = encode_receipt_body(self)?;
        if digest(DomainId::WwmPublicReceipt, &[&body])? != self.receipt_id {
            return Err(GatewayError::InvalidReceipt);
        }
        verify(
            self.gateway_key,
            DomainId::WwmPublicReceipt,
            self.receipt_id,
            &body,
            self.signature,
        )
    }
}

pub struct Gateway {
    signer: Keypair,
    pub manifest: GatewayManifest,
    pub pinned_state: PinnedState,
    pub fee_schedule: FeeSchedule,
    pub rate_policy: RatePolicy,
    test_only: bool,
    rate_usage: BTreeMap<Hash32, RateUsage>,
    sponsors: BTreeMap<Hash32, SponsorAccount>,
    jobs: BTreeMap<Hash32, GatewayJob>,
    receipts: BTreeMap<Hash32, ReceiptView>,
}

impl Gateway {
    pub fn new(
        signer: Keypair,
        manifest: GatewayManifest,
        pinned_state: PinnedState,
        fee_schedule: FeeSchedule,
        rate_policy: RatePolicy,
    ) -> Result<Self, GatewayError> {
        Self::new_with_mode(
            signer,
            manifest,
            pinned_state,
            fee_schedule,
            rate_policy,
            false,
        )
    }

    /// Construct a loopback test gateway without claiming independent state quorum.
    ///
    /// Production controls remain hard-off; callers must disclose this mode.
    pub fn new_test_only(
        signer: Keypair,
        manifest: GatewayManifest,
        pinned_state: PinnedState,
        fee_schedule: FeeSchedule,
        rate_policy: RatePolicy,
    ) -> Result<Self, GatewayError> {
        Self::new_with_mode(
            signer,
            manifest,
            pinned_state,
            fee_schedule,
            rate_policy,
            true,
        )
    }

    fn new_with_mode(
        signer: Keypair,
        manifest: GatewayManifest,
        pinned_state: PinnedState,
        fee_schedule: FeeSchedule,
        rate_policy: RatePolicy,
        test_only: bool,
    ) -> Result<Self, GatewayError> {
        if test_only {
            manifest.validate_test_only()?;
        } else {
            manifest.validate()?;
        }
        if manifest.gateway_key != signer.public_key().into_bytes()
            || fee_schedule.schedule_id != pinned_state.fee_schedule_id
            || rate_policy.window_blocks == 0
            || rate_policy.maximum_requests == 0
            || rate_policy.maximum_output_tokens == 0
            || !valid_pin_shape(&manifest, &pinned_state, test_only)
        {
            return Err(GatewayError::InvalidManifest);
        }
        Ok(Self {
            signer,
            manifest,
            pinned_state,
            fee_schedule,
            rate_policy,
            test_only,
            rate_usage: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            jobs: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn is_test_only(&self) -> bool {
        self.test_only
    }

    pub fn update_pinned_state(&mut self, next: PinnedState) -> Result<(), GatewayError> {
        if !valid_pin_shape(&self.manifest, &next, self.test_only)
            || next.chain_id != self.pinned_state.chain_id
            || next.genesis_hash != self.pinned_state.genesis_hash
            || next.capsule_id != self.pinned_state.capsule_id
            || next.query_policy_id != self.pinned_state.query_policy_id
            || next.knowledge_snapshot_id != self.pinned_state.knowledge_snapshot_id
            || next.executor_registry_epoch != self.pinned_state.executor_registry_epoch
            || next.fee_schedule_id != self.pinned_state.fee_schedule_id
            || next.finalized_height < self.pinned_state.finalized_height
            || (next.finalized_height == self.pinned_state.finalized_height
                && next.finalized_hash != self.pinned_state.finalized_hash)
        {
            return Err(GatewayError::InvalidObservation);
        }
        self.pinned_state = next;
        Ok(())
    }

    pub fn register_sponsor(&mut self, sponsor: SponsorAccount) -> Result<(), GatewayError> {
        if sponsor.sponsor_id == [0; 32]
            || sponsor.remaining_micro_noos == 0
            || sponsor.per_job_cap_micro_noos == 0
            || sponsor.per_job_cap_micro_noos > sponsor.remaining_micro_noos
            || sponsor.expires_height == 0
            || self.sponsors.contains_key(&sponsor.sponsor_id)
        {
            return Err(GatewayError::SponsorPolicy);
        }
        self.sponsors.insert(sponsor.sponsor_id, sponsor);
        Ok(())
    }

    pub fn issue_quote(
        &mut self,
        request: &PublicQueryRequest,
        current_height: u64,
        lifetime_blocks: u32,
    ) -> Result<PublicQuote, GatewayError> {
        request.validate()?;
        if lifetime_blocks == 0 || lifetime_blocks > self.manifest.maximum_quote_lifetime_blocks {
            return Err(GatewayError::InvalidQuote);
        }
        self.consume_rate(request, current_height)?;
        let maximum_fee = self.fee_schedule.maximum_fee(request.bounds)?;
        if let Some(sponsor_id) = request.sponsor_id {
            let sponsor = self
                .sponsors
                .get(&sponsor_id)
                .ok_or(GatewayError::UnknownSponsor)?;
            if current_height >= sponsor.expires_height {
                return Err(GatewayError::SponsorExpired);
            }
            if sponsor
                .allowed_capsule_id
                .is_some_and(|id| id != self.pinned_state.capsule_id)
                || maximum_fee > sponsor.per_job_cap_micro_noos
                || maximum_fee > sponsor.remaining_micro_noos
            {
                return Err(GatewayError::SponsorPolicy);
            }
        }
        let expires_height = current_height
            .checked_add(u64::from(lifetime_blocks))
            .ok_or(GatewayError::ArithmeticOverflow)?;
        let mut quote = PublicQuote {
            gateway_key: self.signer.public_key().into_bytes(),
            pin_id: self.pinned_state.pin_id,
            chain_id: self.pinned_state.chain_id,
            genesis_hash: self.pinned_state.genesis_hash,
            capsule_id: self.pinned_state.capsule_id,
            knowledge_snapshot_id: self.pinned_state.knowledge_snapshot_id,
            query_policy_id: self.pinned_state.query_policy_id,
            fee_schedule_id: self.pinned_state.fee_schedule_id,
            executor_registry_epoch: self.pinned_state.executor_registry_epoch,
            prompt_commitment: request.prompt_commitment,
            client_nonce: request.client_nonce,
            bounds: request.bounds,
            sponsor_id: request.sponsor_id,
            maximum_fee_micro_noos: maximum_fee,
            expires_height,
            quote_id: [0; 32],
            signature: [0; 64],
        };
        let body = quote.body()?;
        quote.quote_id = digest(DomainId::WwmPublicQuote, &[&body])?;
        quote.signature = sign(
            &self.signer,
            DomainId::WwmPublicQuote,
            quote.quote_id,
            &body,
        )?;
        Ok(quote)
    }

    pub fn open_job(
        &mut self,
        quote: &PublicQuote,
        current_height: u64,
    ) -> Result<Hash32, GatewayError> {
        quote.validate()?;
        if current_height >= quote.expires_height
            || quote.gateway_key != self.manifest.gateway_key
            || quote.pin_id != self.pinned_state.pin_id
        {
            return Err(GatewayError::QuoteExpired);
        }
        let job_id = digest(
            DomainId::WwmPublicQuote,
            &[b"JOB", &quote.quote_id, &quote.client_nonce],
        )?;
        if self.jobs.contains_key(&job_id) {
            return Err(GatewayError::DuplicateJob);
        }
        if let Some(sponsor_id) = quote.sponsor_id {
            let sponsor = self
                .sponsors
                .get_mut(&sponsor_id)
                .ok_or(GatewayError::UnknownSponsor)?;
            sponsor.remaining_micro_noos = sponsor
                .remaining_micro_noos
                .checked_sub(quote.maximum_fee_micro_noos)
                .ok_or(GatewayError::SponsorExhausted)?;
        }
        self.jobs.insert(
            job_id,
            GatewayJob {
                job_id,
                quote_id: quote.quote_id,
                prompt_commitment: quote.prompt_commitment,
                capsule_id: quote.capsule_id,
                knowledge_snapshot_id: quote.knowledge_snapshot_id,
                requested_finality: quote.bounds.requested_finality,
                escrow_micro_noos: quote.maximum_fee_micro_noos,
                sponsor_id: quote.sponsor_id,
            },
        );
        Ok(job_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_receipt(
        &mut self,
        job_id: Hash32,
        token_history_root: Hash32,
        retrieval_receipt_id: Option<Hash32>,
        source_mindlink_ids: Vec<Hash32>,
        actual_finality: FinalityClass,
        settlement_id: Hash32,
        charged_micro_noos: u64,
    ) -> Result<Hash32, GatewayError> {
        let job = self.jobs.get(&job_id).ok_or(GatewayError::UnknownJob)?;
        if token_history_root == [0; 32]
            || settlement_id == [0; 32]
            || retrieval_receipt_id == Some([0; 32])
            || source_mindlink_ids.len() > MAX_RECEIPT_SOURCES
            || !strictly_sorted(&source_mindlink_ids)
            || source_mindlink_ids.contains(&[0; 32])
            || actual_finality > job.requested_finality
            || charged_micro_noos > job.escrow_micro_noos
        {
            return Err(if actual_finality > job.requested_finality {
                GatewayError::FinalityOverstatement
            } else {
                GatewayError::InvalidReceipt
            });
        }
        let refunded = job
            .escrow_micro_noos
            .checked_sub(charged_micro_noos)
            .ok_or(GatewayError::ArithmeticOverflow)?;
        let gateway_key = self.signer.public_key().into_bytes();
        let mut view = ReceiptView {
            gateway_key,
            job_id,
            quote_id: job.quote_id,
            capsule_id: job.capsule_id,
            knowledge_snapshot_id: job.knowledge_snapshot_id,
            token_history_root,
            retrieval_receipt_id,
            source_mindlink_ids,
            actual_finality,
            assurance_label: assurance_label(actual_finality),
            settlement_id,
            charged_micro_noos,
            refunded_micro_noos: refunded,
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        let body = encode_receipt_body(&view)?;
        view.receipt_id = digest(DomainId::WwmPublicReceipt, &[&body])?;
        view.signature = sign(
            &self.signer,
            DomainId::WwmPublicReceipt,
            view.receipt_id,
            &body,
        )?;
        let receipt_id = view.receipt_id;
        if let Some(sponsor_id) = job.sponsor_id {
            let sponsor = self
                .sponsors
                .get_mut(&sponsor_id)
                .ok_or(GatewayError::UnknownSponsor)?;
            sponsor.remaining_micro_noos = sponsor
                .remaining_micro_noos
                .checked_add(refunded)
                .ok_or(GatewayError::ArithmeticOverflow)?;
        }
        self.receipts.insert(receipt_id, view);
        Ok(receipt_id)
    }

    #[must_use]
    pub fn receipt(&self, receipt_id: &Hash32) -> Option<&ReceiptView> {
        self.receipts.get(receipt_id)
    }

    fn consume_rate(
        &mut self,
        request: &PublicQueryRequest,
        current_height: u64,
    ) -> Result<(), GatewayError> {
        let usage = self
            .rate_usage
            .entry(request.requester_credential)
            .or_insert(RateUsage {
                window_start: current_height,
                requests: 0,
                output_tokens: 0,
            });
        if current_height
            >= usage
                .window_start
                .saturating_add(self.rate_policy.window_blocks)
        {
            *usage = RateUsage {
                window_start: current_height,
                requests: 0,
                output_tokens: 0,
            };
        }
        let requests = usage
            .requests
            .checked_add(1)
            .ok_or(GatewayError::ArithmeticOverflow)?;
        let tokens = usage
            .output_tokens
            .checked_add(request.bounds.maximum_output_tokens)
            .ok_or(GatewayError::ArithmeticOverflow)?;
        if requests > self.rate_policy.maximum_requests
            || tokens > self.rate_policy.maximum_output_tokens
        {
            return Err(GatewayError::RateLimited);
        }
        usage.requests = requests;
        usage.output_tokens = tokens;
        Ok(())
    }
}

fn encode_receipt_body(receipt: &ReceiptView) -> Result<Vec<u8>, GatewayError> {
    let mut body = Vec::new();
    body.extend(receipt.gateway_key);
    body.extend(receipt.job_id);
    body.extend(receipt.quote_id);
    body.extend(receipt.capsule_id);
    body.extend(receipt.knowledge_snapshot_id);
    body.extend(receipt.token_history_root);
    match receipt.retrieval_receipt_id {
        Some(id) => {
            body.push(1);
            body.extend(id);
        }
        None => body.push(0),
    }
    push_hashes(&mut body, &receipt.source_mindlink_ids)?;
    body.push(finality_code(receipt.actual_finality)?);
    body.extend(receipt.settlement_id);
    body.extend(receipt.charged_micro_noos.to_le_bytes());
    body.extend(receipt.refunded_micro_noos.to_le_bytes());
    Ok(body)
}

fn valid_pin_shape(manifest: &GatewayManifest, pin: &PinnedState, test_only: bool) -> bool {
    let minimum = if test_only { 1 } else { STATE_QUORUM };
    pin.pin_id != [0; 32]
        && pin.chain_id != [0; 32]
        && pin.genesis_hash != [0; 32]
        && pin.finalized_height != 0
        && pin.finalized_hash != [0; 32]
        && pin.capsule_id != [0; 32]
        && pin.query_policy_id != [0; 32]
        && pin.knowledge_snapshot_id != [0; 32]
        && pin.executor_registry_epoch != 0
        && pin.fee_schedule_id != [0; 32]
        && pin.agreeing_endpoints.len() >= minimum
        && pin.agreeing_control_clusters.len() >= minimum
        && strictly_sorted(&pin.agreeing_endpoints)
        && strictly_sorted(&pin.agreeing_control_clusters)
        && pin
            .agreeing_endpoints
            .iter()
            .all(|value| manifest.state_endpoint_ids.contains(value))
        && pin
            .agreeing_control_clusters
            .iter()
            .all(|value| manifest.state_control_clusters.contains(value))
}

#[must_use]
pub const fn assurance_label(finality: FinalityClass) -> &'static str {
    match finality {
        FinalityClass::Soft => "SOFT",
        FinalityClass::Anchored => "ANCHORED",
        FinalityClass::Assured => "ASSURED",
        FinalityClass::Proven => "PROVEN",
    }
}

fn finality_code(finality: FinalityClass) -> Result<u8, GatewayError> {
    match finality {
        FinalityClass::Soft => Ok(0),
        FinalityClass::Anchored => Ok(1),
        FinalityClass::Assured => Ok(2),
        FinalityClass::Proven => Ok(3),
    }
}

fn encode_pin_body(
    state: &StateTuple,
    endpoints: &[Hash32],
    clusters: &[Hash32],
) -> Result<Vec<u8>, GatewayError> {
    let mut body = Vec::with_capacity(330);
    body.extend(state.chain_id);
    body.extend(state.genesis_hash);
    body.extend(state.finalized_height.to_le_bytes());
    body.extend(state.finalized_hash);
    body.extend(state.capsule_id);
    body.extend(state.query_policy_id);
    body.extend(state.knowledge_snapshot_id);
    body.extend(state.executor_registry_epoch.to_le_bytes());
    body.extend(state.fee_schedule_id);
    push_hashes(&mut body, endpoints)?;
    push_hashes(&mut body, clusters)?;
    Ok(body)
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), GatewayError> {
    let count = u16::try_from(values.len()).map_err(|_| GatewayError::ArithmeticOverflow)?;
    out.extend(count.to_le_bytes());
    for value in values {
        out.extend(value);
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, GatewayError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| GatewayError::InvalidQuote)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], GatewayError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| GatewayError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), GatewayError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| GatewayError::InvalidSignature)
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

    fn observations() -> Vec<StateObservation> {
        (0_u8..3)
            .map(|index| StateObservation {
                endpoint_id: h(20 + index),
                control_cluster: h(30 + index),
                chain_id: h(1),
                genesis_hash: h(2),
                finalized_height: 50,
                finalized_hash: h(3),
                capsule_id: h(4),
                query_policy_id: h(5),
                knowledge_snapshot_id: h(6),
                executor_registry_epoch: 9,
                fee_schedule_id: h(7),
            })
            .collect()
    }

    fn gateway() -> Gateway {
        let signer = Keypair::from_seed([90; 32]);
        let pinned = pin_state(&observations()).unwrap();
        Gateway::new(
            signer,
            GatewayManifest {
                gateway_key: Keypair::from_seed([90; 32]).public_key().into_bytes(),
                state_endpoint_ids: vec![h(20), h(21), h(22)],
                state_control_clusters: vec![h(30), h(31), h(32)],
                api_version: 1,
                maximum_quote_lifetime_blocks: 20,
            },
            pinned,
            FeeSchedule {
                schedule_id: h(7),
                base_micro_noos: 100,
                input_token_micro_noos: 2,
                retrieval_token_micro_noos: 1,
                output_token_micro_noos: 5,
                anchored_surcharge_micro_noos: 20,
                assured_surcharge_micro_noos: 50,
            },
            RatePolicy {
                window_blocks: 10,
                maximum_requests: 2,
                maximum_output_tokens: 128,
            },
        )
        .unwrap()
    }

    fn request(sponsor_id: Option<Hash32>) -> PublicQueryRequest {
        PublicQueryRequest {
            requester_credential: h(40),
            prompt_commitment: h(41),
            bounds: QueryBounds {
                input_tokens: 16,
                retrieved_context_tokens: 32,
                maximum_output_tokens: 64,
                requested_finality: FinalityClass::Assured,
            },
            sponsor_id,
            client_nonce: h(42),
        }
    }

    #[test]
    fn state_pin_uses_independent_quorum_and_rejects_split() {
        let pin = pin_state(&observations()).unwrap();
        assert_eq!(pin.agreeing_endpoints.len(), 3);
        let mut split = observations();
        split[1].finalized_hash = h(99);
        split[2].finalized_hash = h(98);
        assert_eq!(
            pin_state(&split),
            Err(GatewayError::InsufficientStateQuorum)
        );
    }

    #[test]
    fn signed_quote_binds_model_snapshot_fee_and_sponsor_cap() {
        let mut gateway = gateway();
        gateway
            .register_sponsor(SponsorAccount {
                sponsor_id: h(70),
                remaining_micro_noos: 10_000,
                per_job_cap_micro_noos: 1_000,
                allowed_capsule_id: Some(h(4)),
                expires_height: 100,
            })
            .unwrap();
        let quote = gateway.issue_quote(&request(Some(h(70))), 50, 5).unwrap();
        quote.validate().unwrap();
        assert_eq!(quote.capsule_id, h(4));
        assert_eq!(quote.knowledge_snapshot_id, h(6));
        assert_eq!(quote.maximum_fee_micro_noos, 534);
        let job = gateway.open_job(&quote, 51).unwrap();
        let receipt = gateway
            .record_receipt(
                job,
                h(80),
                Some(h(81)),
                vec![h(82), h(83)],
                FinalityClass::Anchored,
                h(84),
                400,
            )
            .unwrap();
        let view = gateway.receipt(&receipt).unwrap();
        view.validate().unwrap();
        let mut tampered = view.clone();
        tampered.signature[0] ^= 1;
        assert_eq!(tampered.validate(), Err(GatewayError::InvalidSignature));
        assert_eq!(view.assurance_label, "ANCHORED");
        assert_eq!(view.refunded_micro_noos, 134);
    }

    #[test]
    fn rate_limit_and_finality_overstatement_fail_closed() {
        let mut gateway = gateway();
        let first = gateway.issue_quote(&request(None), 50, 5).unwrap();
        let mut second_request = request(None);
        second_request.client_nonce = h(43);
        gateway.issue_quote(&second_request, 50, 5).unwrap();
        let mut third_request = request(None);
        third_request.client_nonce = h(44);
        assert_eq!(
            gateway.issue_quote(&third_request, 50, 5),
            Err(GatewayError::RateLimited)
        );
        let job = gateway.open_job(&first, 51).unwrap();
        assert_eq!(
            gateway.record_receipt(job, h(80), None, vec![], FinalityClass::Proven, h(84), 400),
            Err(GatewayError::FinalityOverstatement)
        );
    }

    #[test]
    fn gateway_is_replaceable_and_never_consensus_weighted() {
        assert!(!WWM_PUBLIC_GATEWAY_ENABLED);
        assert_eq!(WWM_GATEWAY_CONSENSUS_WEIGHT, 0);
    }
}
