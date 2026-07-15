//! Finalized, proof-carrying WWM model/config resolution.
//!
//! Construction requires an explicit finalized ledger snapshot whose objects
//! root equals the finalized header. Verification requires a separately
//! verified finalized checkpoint. Neither path treats an RPC/P2P endpoint as
//! authority, and an unsafe-head ledger cannot be substituted silently.

use std::collections::BTreeSet;

use noos_braid::{BlockHeaderV1, CheckpointRef, FinalityCertificateV1};
use noos_codec::{define_object, NoosDecode, NoosEncode};
use noos_lumen::objects::{BoundedBytes, BoundedList};
use noos_lumen::state::LumenLedger;
use noos_lumen::wwm::{
    certificate_key, current_certificate_pointer_key, decode_certificate_pointer,
    serving_alias_key, wwm_fixed_key, wwm_profile_key, ArtifactDescriptorV1,
    AuthorizedConfigResolutionV1, AvailabilityCertificateV2, AvailabilityPolicyV2, CapabilitySetV1,
    CustodianCapabilitySetV1, ExecutionProfileV1, FeePolicyV1, FinalizedModelResolutionV1,
    FundProfileV1, ModelCapsuleV2, OperationalReconfigurationV1, QueryPolicyV1,
    RegistryEpochVectorV1, ResolutionProofV1, ResolutionSelectorKind, ResolutionSelectorV1,
    ResolutionValueV1, ServiceDirectoryV1, ServingAliasTransitionV1, WwmAuthorizedConfigV1,
    WwmControlStateV1, WwmFundLedgerV1, WwmLeafKind, MAX_AUTHORIZED_RESOLUTION_BYTES,
    MAX_FINALIZED_RESOLUTION_BYTES,
};

use crate::Hash32;

/// Terminal material carried inside `FinalizedModelResolutionV1`.
define_object! {
    pub struct FinalizedResolutionTerminalV1 {
        version: 1;
        1 => header: BlockHeaderV1,
        2 => checkpoint: CheckpointRef,
        3 => finality: FinalityCertificateV1,
    }
}

/// Current terminal material for candidate review. The current control proof is
/// necessary to prove that a published candidate remains authorized but is not
/// active at the current finalized root.
define_object! {
    pub struct AuthorizedResolutionTerminalV1 {
        version: 1;
        1 => terminal: FinalizedResolutionTerminalV1,
        2 => current_control: ResolutionProofV1,
    }
}

/// A checkpoint accepted only after local light/full consensus verification.
/// It is supplied independently of the resolver response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedFinalizedCheckpointV1 {
    pub checkpoint: CheckpointRef,
    pub height: u64,
}

/// Stable resolver failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionError {
    IdentityMismatch,
    SelectorMismatch,
    FreshnessExceeded,
    UnsafeStateRoot,
    TerminalMalformed,
    TerminalNotFinalized,
    ProofInvalid,
    ProofSetMismatch,
    MissingValue,
    UnexpectedValue,
    ValueMalformed,
    ReferenceMismatch,
    InvariantViolation,
    ByteBudgetExceeded,
    CandidateActive,
    CandidateExpired,
}

/// Fully decoded active resolution. Keeping decoded objects makes it impossible
/// for callers to accidentally dispatch from unverified response bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedModelResolutionV1 {
    pub terminal: FinalizedResolutionTerminalV1,
    pub alias: Option<ServingAliasTransitionV1>,
    pub control: WwmControlStateV1,
    pub config: Option<WwmAuthorizedConfigV1>,
    pub capsule: Option<ModelCapsuleV2>,
    pub artifact: Option<ArtifactDescriptorV1>,
    pub availability_policy: Option<AvailabilityPolicyV2>,
    pub availability_certificate: Option<AvailabilityCertificateV2>,
    pub registry: Option<RegistryEpochVectorV1>,
    pub executor_set: Option<CapabilitySetV1>,
    pub custodian_set: Option<CustodianCapabilitySetV1>,
    pub execution_profile: Option<ExecutionProfileV1>,
    pub query_policy: Option<QueryPolicyV1>,
    pub fee_policy: Option<FeePolicyV1>,
    pub fund_profile: Option<FundProfileV1>,
    pub fund_ledger: Option<WwmFundLedgerV1>,
    pub service_directory: Option<ServiceDirectoryV1>,
}

/// Verified publication result. This status is deliberately distinct from an
/// active model resolution and cannot be used for admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorizedConfigV1 {
    pub parent: VerifiedModelResolutionV1,
    pub current_terminal: AuthorizedResolutionTerminalV1,
    pub candidate: OperationalReconfigurationV1,
    pub staged_fund_profile: Option<FundProfileV1>,
    pub staged_fund_ledger: Option<WwmFundLedgerV1>,
}

fn present_bytes(proof: &ResolutionProofV1) -> Result<&[u8], ResolutionError> {
    if !proof.verify() {
        return Err(ResolutionError::ProofInvalid);
    }
    match &proof.value {
        ResolutionValueV1::Present(value) => Ok(value.as_slice()),
        ResolutionValueV1::Absent => Err(ResolutionError::MissingValue),
    }
}

fn decode_present<T: NoosDecode>(proof: &ResolutionProofV1) -> Result<T, ResolutionError> {
    T::decode_canonical(present_bytes(proof)?).map_err(|_| ResolutionError::ValueMalformed)
}

fn proof_at<'a>(
    response: &'a FinalizedModelResolutionV1,
    key: &Hash32,
) -> Result<&'a ResolutionProofV1, ResolutionError> {
    response
        .proofs
        .as_slice()
        .binary_search_by_key(key, |proof| proof.state_key)
        .ok()
        .and_then(|index| response.proofs.as_slice().get(index))
        .ok_or(ResolutionError::ProofSetMismatch)
}

fn decode_terminal(
    bytes: &[u8],
    resolution_height: u64,
    trusted: TrustedFinalizedCheckpointV1,
) -> Result<FinalizedResolutionTerminalV1, ResolutionError> {
    let terminal = FinalizedResolutionTerminalV1::decode_canonical(bytes)
        .map_err(|_| ResolutionError::TerminalMalformed)?;
    let hash = terminal
        .header
        .block_hash()
        .map_err(|_| ResolutionError::TerminalMalformed)?
        .into_bytes();
    if terminal.header.height != resolution_height
        || trusted.height != resolution_height
        || terminal.checkpoint != trusted.checkpoint
        || terminal.checkpoint.checkpoint_hash != hash
        || terminal.finality.source != terminal.checkpoint
    {
        return Err(ResolutionError::TerminalNotFinalized);
    }
    Ok(terminal)
}

fn require_key(expected: &mut BTreeSet<Hash32>, kind: WwmLeafKind, id: &Hash32) -> Hash32 {
    let key = wwm_profile_key(kind, id);
    expected.insert(key);
    key
}

fn verify_active_graph(
    response: &FinalizedModelResolutionV1,
    terminal: FinalizedResolutionTerminalV1,
) -> Result<VerifiedModelResolutionV1, ResolutionError> {
    let mut expected = BTreeSet::new();

    let alias = match response.selector.kind {
        ResolutionSelectorKind::Alias => {
            let key = serving_alias_key();
            expected.insert(key);
            let value: ServingAliasTransitionV1 = decode_present(proof_at(response, &key)?)?;
            if value.alias.as_slice() != response.selector.value.as_slice() {
                return Err(ResolutionError::SelectorMismatch);
            }
            Some(value)
        }
        ResolutionSelectorKind::Capsule => None,
    };

    let control_key = wwm_fixed_key(WwmLeafKind::Control);
    expected.insert(control_key);
    let control: WwmControlStateV1 = decode_present(proof_at(response, &control_key)?)?;
    if !control.separation_valid() {
        return Err(ResolutionError::InvariantViolation);
    }

    let config_id = control.resolution_config_id.0.unwrap_or([0_u8; 32]);
    let config_key = require_key(&mut expected, WwmLeafKind::AuthorizedConfig, &config_id);
    let config_proof = proof_at(response, &config_key)?;
    let config = match (&control.resolution_config_id.0, &config_proof.value) {
        (None, ResolutionValueV1::Absent) => {
            if control.active_config_id.0.is_some() {
                return Err(ResolutionError::InvariantViolation);
            }
            None
        }
        (Some(id), ResolutionValueV1::Present(_)) => {
            let value: WwmAuthorizedConfigV1 = decode_present(config_proof)?;
            if value.config_id != *id || !value.validate() {
                return Err(ResolutionError::ReferenceMismatch);
            }
            Some(value)
        }
        _ => return Err(ResolutionError::UnexpectedValue),
    };

    let Some(config) = config else {
        if response.proofs.len() != expected.len() {
            return Err(ResolutionError::ProofSetMismatch);
        }
        return Ok(VerifiedModelResolutionV1 {
            terminal,
            alias,
            control,
            config: None,
            capsule: None,
            artifact: None,
            availability_policy: None,
            availability_certificate: None,
            registry: None,
            executor_set: None,
            custodian_set: None,
            execution_profile: None,
            query_policy: None,
            fee_policy: None,
            fund_profile: None,
            fund_ledger: None,
            service_directory: None,
        });
    };

    let capsule_id = match response.selector.kind {
        ResolutionSelectorKind::Alias => alias
            .as_ref()
            .map(|value| value.new_capsule_id)
            .ok_or(ResolutionError::SelectorMismatch)?,
        ResolutionSelectorKind::Capsule => response
            .selector
            .value
            .as_slice()
            .try_into()
            .map_err(|_| ResolutionError::SelectorMismatch)?,
    };
    if capsule_id != config.capsule_id || control.capsule_id != capsule_id {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let capsule_key = require_key(&mut expected, WwmLeafKind::Capsule, &capsule_id);
    let capsule: ModelCapsuleV2 = decode_present(proof_at(response, &capsule_key)?)?;
    if capsule.capsule_id != capsule_id
        || capsule.artifact_id != config.artifact_id
        || capsule.availability_policy_id != config.availability_policy_id
        || capsule.query_policy_id != config.query_policy_id
        || !capsule
            .execution_profile_ids
            .as_slice()
            .contains(&config.execution_profile_id)
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let artifact_key = require_key(&mut expected, WwmLeafKind::Artifact, &config.artifact_id);
    let artifact: ArtifactDescriptorV1 = decode_present(proof_at(response, &artifact_key)?)?;
    if artifact.artifact_id != config.artifact_id
        || artifact.payload_root != capsule.payload_root
        || artifact.manifest_root != capsule.manifest_root
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let policy_key = require_key(
        &mut expected,
        WwmLeafKind::AvailabilityPolicy,
        &config.availability_policy_id,
    );
    let availability_policy: AvailabilityPolicyV2 =
        decode_present(proof_at(response, &policy_key)?)?;
    if availability_policy.policy_id != config.availability_policy_id
        || availability_policy.artifact_id != config.artifact_id
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let pointer_key = current_certificate_pointer_key();
    expected.insert(pointer_key);
    let certificate_id =
        decode_certificate_pointer(present_bytes(proof_at(response, &pointer_key)?)?)
            .ok_or(ResolutionError::ValueMalformed)?;
    let certificate_state_key =
        require_key(&mut expected, WwmLeafKind::Certificate, &certificate_id);
    let availability_certificate: AvailabilityCertificateV2 =
        decode_present(proof_at(response, &certificate_state_key)?)?;
    if availability_certificate.certificate_id != certificate_id
        || availability_certificate.policy_id != config.availability_policy_id
        || availability_certificate.artifact_id != config.artifact_id
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let registry_key = wwm_fixed_key(WwmLeafKind::RegistryEpochVector);
    expected.insert(registry_key);
    let registry: RegistryEpochVectorV1 = decode_present(proof_at(response, &registry_key)?)?;
    if registry.fee_policy_id != config.fee_policy_id
        || registry.fund_profile_id != config.fund_profile_id
        || registry.service_directory_id != config.service_directory_id
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let executor_key = require_key(
        &mut expected,
        WwmLeafKind::ExecutorCapabilitySet,
        &registry.executor_set_id,
    );
    let executor_set: CapabilitySetV1 = decode_present(proof_at(response, &executor_key)?)?;
    if executor_set.set_id != registry.executor_set_id
        || executor_set.epoch != registry.executor_epoch
        || !executor_set.validate()
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let custodian_key = require_key(
        &mut expected,
        WwmLeafKind::CustodianCapabilitySet,
        &registry.custodian_set_id,
    );
    let custodian_set: CustodianCapabilitySetV1 =
        decode_present(proof_at(response, &custodian_key)?)?;
    if custodian_set.set_id != registry.custodian_set_id
        || custodian_set.epoch != registry.custodian_epoch
        || !custodian_set.validate()
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    if availability_certificate.executor_set_id != executor_set.set_id
        || availability_certificate.executor_set_epoch != executor_set.epoch
        || availability_certificate.custodian_set_id != custodian_set.set_id
        || availability_certificate.custodian_set_epoch != custodian_set.epoch
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let execution_key = require_key(
        &mut expected,
        WwmLeafKind::ExecutionProfile,
        &config.execution_profile_id,
    );
    let execution_profile: ExecutionProfileV1 =
        decode_present(proof_at(response, &execution_key)?)?;
    if execution_profile.profile_id != config.execution_profile_id
        || execution_profile.capsule_id != capsule_id
        || execution_profile.runtime_root != capsule.runtime_root
        || execution_profile.tokenizer_root != capsule.tokenizer_root
        || execution_profile.template_root != capsule.template_root
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let query_key = require_key(
        &mut expected,
        WwmLeafKind::QueryPolicy,
        &config.query_policy_id,
    );
    let query_policy: QueryPolicyV1 = decode_present(proof_at(response, &query_key)?)?;
    if query_policy.policy_id != config.query_policy_id || query_policy.capsule_id != capsule_id {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let fee_key = require_key(
        &mut expected,
        WwmLeafKind::FeePolicy,
        &registry.fee_policy_id,
    );
    let fee_policy: FeePolicyV1 = decode_present(proof_at(response, &fee_key)?)?;
    if fee_policy.policy_id != registry.fee_policy_id {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let fund_key = require_key(
        &mut expected,
        WwmLeafKind::FundProfile,
        &registry.fund_profile_id,
    );
    let fund_profile: FundProfileV1 = decode_present(proof_at(response, &fund_key)?)?;
    if fund_profile.profile_id != registry.fund_profile_id || !fund_profile.validate() {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let ledger_key = require_key(
        &mut expected,
        WwmLeafKind::FundLedger,
        &registry.fund_profile_id,
    );
    let fund_ledger: WwmFundLedgerV1 = decode_present(proof_at(response, &ledger_key)?)?;
    if fund_ledger.profile_id != registry.fund_profile_id || !fund_ledger.validate() {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let service_key = require_key(
        &mut expected,
        WwmLeafKind::ServiceDirectory,
        &registry.service_directory_id,
    );
    let service_directory: ServiceDirectoryV1 = decode_present(proof_at(response, &service_key)?)?;
    if service_directory.directory_id != registry.service_directory_id
        || service_directory.epoch != registry.service_epoch
    {
        return Err(ResolutionError::ReferenceMismatch);
    }

    if response.proofs.len() != expected.len()
        || response
            .proofs
            .iter()
            .any(|proof| !expected.contains(&proof.state_key))
    {
        return Err(ResolutionError::ProofSetMismatch);
    }

    Ok(VerifiedModelResolutionV1 {
        terminal,
        alias,
        control,
        config: Some(config),
        capsule: Some(capsule),
        artifact: Some(artifact),
        availability_policy: Some(availability_policy),
        availability_certificate: Some(availability_certificate),
        registry: Some(registry),
        executor_set: Some(executor_set),
        custodian_set: Some(custodian_set),
        execution_profile: Some(execution_profile),
        query_policy: Some(query_policy),
        fee_policy: Some(fee_policy),
        fund_profile: Some(fund_profile),
        fund_ledger: Some(fund_ledger),
        service_directory: Some(service_directory),
    })
}

/// Verifies identity, freshness, independently trusted finality, every SMT
/// proof, every one of the active 17 leaves, and all parent-derived IDs.
pub fn verify_finalized_model_resolution(
    response: &FinalizedModelResolutionV1,
    expected_chain_id: Hash32,
    expected_genesis_hash: Hash32,
    expected_selector: &ResolutionSelectorV1,
    trusted: TrustedFinalizedCheckpointV1,
    current_finalized_height: u64,
) -> Result<VerifiedModelResolutionV1, ResolutionError> {
    if response.chain_id != expected_chain_id || response.genesis_hash != expected_genesis_hash {
        return Err(ResolutionError::IdentityMismatch);
    }
    if &response.selector != expected_selector {
        return Err(ResolutionError::SelectorMismatch);
    }
    if current_finalized_height < response.resolution_height
        || current_finalized_height.saturating_sub(response.resolution_height)
            > response.freshness_bound
    {
        return Err(ResolutionError::FreshnessExceeded);
    }
    if !response.validate() || response.encode_canonical().len() > MAX_FINALIZED_RESOLUTION_BYTES {
        return Err(ResolutionError::ByteBudgetExceeded);
    }
    let terminal = decode_terminal(
        response.terminal_material.as_slice(),
        response.resolution_height,
        trusted,
    )?;
    if response
        .proofs
        .iter()
        .any(|proof| proof.objects_root != terminal.header.objects_root || !proof.verify())
    {
        return Err(ResolutionError::ProofInvalid);
    }
    verify_active_graph(response, terminal)
}

/// Constructs a response from an explicitly supplied finalized ledger snapshot.
/// The root equality check is the unsafe-versus-finalized guard.
pub fn build_finalized_model_resolution(
    ledger: &LumenLedger,
    chain_id: Hash32,
    genesis_hash: Hash32,
    selector: ResolutionSelectorV1,
    freshness_bound: u64,
    terminal: FinalizedResolutionTerminalV1,
) -> Result<FinalizedModelResolutionV1, ResolutionError> {
    if terminal.header.objects_root != ledger.roots().objects_root {
        return Err(ResolutionError::UnsafeStateRoot);
    }
    let resolution_height = terminal.header.height;
    let terminal_material = BoundedBytes::new(terminal.encode_canonical())
        .ok_or(ResolutionError::ByteBudgetExceeded)?;

    let mut proofs = Vec::new();
    if selector.kind == ResolutionSelectorKind::Alias {
        proofs.push(ledger.finalized_object_proof(serving_alias_key()));
    }
    let control_key = wwm_fixed_key(WwmLeafKind::Control);
    let control_proof = ledger.finalized_object_proof(control_key);
    let control: WwmControlStateV1 = decode_present(&control_proof)?;
    proofs.push(control_proof);

    let config_id = control.resolution_config_id.0.unwrap_or([0_u8; 32]);
    let config_key = wwm_profile_key(WwmLeafKind::AuthorizedConfig, &config_id);
    let config_proof = ledger.finalized_object_proof(config_key);
    let config = match control.resolution_config_id.0 {
        Some(_) => Some(decode_present::<WwmAuthorizedConfigV1>(&config_proof)?),
        None => None,
    };
    proofs.push(config_proof);

    if let Some(config) = config {
        let capsule_id = match selector.kind {
            ResolutionSelectorKind::Alias => {
                let alias: ServingAliasTransitionV1 =
                    decode_present(&ledger.finalized_object_proof(serving_alias_key()))?;
                alias.new_capsule_id
            }
            ResolutionSelectorKind::Capsule => selector
                .value
                .as_slice()
                .try_into()
                .map_err(|_| ResolutionError::SelectorMismatch)?,
        };
        let capsule_proof =
            ledger.finalized_object_proof(wwm_profile_key(WwmLeafKind::Capsule, &capsule_id));
        let capsule: ModelCapsuleV2 = decode_present(&capsule_proof)?;
        proofs.push(capsule_proof);
        proofs.push(
            ledger.finalized_object_proof(wwm_profile_key(
                WwmLeafKind::Artifact,
                &config.artifact_id,
            )),
        );
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::AvailabilityPolicy,
            &config.availability_policy_id,
        )));
        let pointer = ledger.finalized_object_proof(current_certificate_pointer_key());
        let certificate_id = decode_certificate_pointer(present_bytes(&pointer)?)
            .ok_or(ResolutionError::ValueMalformed)?;
        proofs.push(pointer);
        proofs.push(ledger.finalized_object_proof(certificate_key(&certificate_id)));
        let registry_key = wwm_fixed_key(WwmLeafKind::RegistryEpochVector);
        let registry_proof = ledger.finalized_object_proof(registry_key);
        let registry: RegistryEpochVectorV1 = decode_present(&registry_proof)?;
        proofs.push(registry_proof);
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::ExecutorCapabilitySet,
            &registry.executor_set_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::CustodianCapabilitySet,
            &registry.custodian_set_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::ExecutionProfile,
            &config.execution_profile_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::QueryPolicy,
            &capsule.query_policy_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::FeePolicy,
            &registry.fee_policy_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::FundProfile,
            &registry.fund_profile_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::FundLedger,
            &registry.fund_profile_id,
        )));
        proofs.push(ledger.finalized_object_proof(wwm_profile_key(
            WwmLeafKind::ServiceDirectory,
            &registry.service_directory_id,
        )));
    }

    proofs.sort_by_key(|proof| proof.state_key);
    if proofs
        .windows(2)
        .any(|pair| pair[0].state_key == pair[1].state_key)
    {
        return Err(ResolutionError::ProofSetMismatch);
    }
    let proofs = BoundedList::new(proofs).ok_or(ResolutionError::ProofSetMismatch)?;
    let response = FinalizedModelResolutionV1 {
        chain_id,
        genesis_hash,
        selector,
        freshness_bound,
        resolution_height,
        terminal_material,
        proofs,
    };
    if !response.validate() || response.encode_canonical().len() > MAX_FINALIZED_RESOLUTION_BYTES {
        return Err(ResolutionError::ByteBudgetExceeded);
    }
    Ok(response)
}

/// Verifies a publication candidate at a current finalized checkpoint and
/// returns the explicit `AUTHORIZED_NOT_ACTIVE` status object.
pub fn verify_authorized_config_resolution(
    response: &AuthorizedConfigResolutionV1,
    expected_chain_id: Hash32,
    expected_genesis_hash: Hash32,
    expected_selector: &ResolutionSelectorV1,
    parent_trusted: TrustedFinalizedCheckpointV1,
    current_trusted: TrustedFinalizedCheckpointV1,
    current_finalized_height: u64,
) -> Result<VerifiedAuthorizedConfigV1, ResolutionError> {
    if !response.validate() || response.encode_canonical().len() > MAX_AUTHORIZED_RESOLUTION_BYTES {
        return Err(ResolutionError::ByteBudgetExceeded);
    }
    let parent = verify_finalized_model_resolution(
        &response.parent,
        expected_chain_id,
        expected_genesis_hash,
        expected_selector,
        parent_trusted,
        parent_trusted.height,
    )?;
    let current_terminal = AuthorizedResolutionTerminalV1::decode_canonical(
        response.current_terminal_material.as_slice(),
    )
    .map_err(|_| ResolutionError::TerminalMalformed)?;
    let checked_terminal = decode_terminal(
        &current_terminal.terminal.encode_canonical(),
        current_trusted.height,
        current_trusted,
    )?;
    if checked_terminal != current_terminal.terminal
        || current_terminal.current_control.objects_root
            != current_terminal.terminal.header.objects_root
        || current_terminal.current_control.state_key != wwm_fixed_key(WwmLeafKind::Control)
    {
        return Err(ResolutionError::ProofInvalid);
    }
    let current_control: WwmControlStateV1 = decode_present(&current_terminal.current_control)?;
    if !current_control.separation_valid() {
        return Err(ResolutionError::InvariantViolation);
    }

    let candidate = &response.candidate;
    if candidate.chain_id != expected_chain_id
        || candidate.genesis_hash != expected_genesis_hash
        || candidate.parent_resolution_height != response.parent.resolution_height
    {
        return Err(ResolutionError::IdentityMismatch);
    }
    let parent_active = parent
        .control
        .active_config_id
        .0
        .ok_or(ResolutionError::ReferenceMismatch)?;
    if candidate.prior_active_config_id != parent_active
        || candidate.candidate_config.parent_config_id.0 != Some(parent_active)
        || !candidate.candidate_config.validate()
    {
        return Err(ResolutionError::ReferenceMismatch);
    }
    if current_control.active_config_id.0 == Some(candidate.candidate_config.config_id)
        || current_control.resolution_config_id.0 == Some(candidate.candidate_config.config_id)
    {
        return Err(ResolutionError::CandidateActive);
    }
    if current_control.latest_authorized_config_id.0 != Some(candidate.candidate_config.config_id) {
        return Err(ResolutionError::ReferenceMismatch);
    }
    if current_finalized_height < candidate.issued_height
        || current_finalized_height > candidate.expiry_height
    {
        return Err(ResolutionError::CandidateExpired);
    }

    let authorization_key = wwm_profile_key(
        WwmLeafKind::OperationalAuthorization,
        &candidate.authorization_id,
    );
    let authorization_proof = response
        .proofs
        .iter()
        .find(|proof| proof.state_key == authorization_key)
        .ok_or(ResolutionError::ProofSetMismatch)?;
    if authorization_proof.objects_root != current_terminal.terminal.header.objects_root {
        return Err(ResolutionError::ProofInvalid);
    }
    let proved_candidate: OperationalReconfigurationV1 = decode_present(authorization_proof)?;
    if proved_candidate != *candidate {
        return Err(ResolutionError::ReferenceMismatch);
    }

    let mut staged_fund_profile = None;
    let mut staged_fund_ledger = None;
    for proof in response
        .proofs
        .iter()
        .filter(|proof| proof.state_key != authorization_key)
    {
        if proof.objects_root != current_terminal.terminal.header.objects_root {
            return Err(ResolutionError::ProofInvalid);
        }
        let profile_key = wwm_profile_key(
            WwmLeafKind::FundProfile,
            &candidate.candidate_config.fund_profile_id,
        );
        let ledger_key = wwm_profile_key(
            WwmLeafKind::FundLedger,
            &candidate.candidate_config.fund_profile_id,
        );
        if proof.state_key == profile_key {
            let value: FundProfileV1 = decode_present(proof)?;
            if value.profile_id != candidate.candidate_config.fund_profile_id || !value.validate() {
                return Err(ResolutionError::ReferenceMismatch);
            }
            staged_fund_profile = Some(value);
        } else if proof.state_key == ledger_key {
            let value: WwmFundLedgerV1 = decode_present(proof)?;
            if value.profile_id != candidate.candidate_config.fund_profile_id || !value.validate() {
                return Err(ResolutionError::ReferenceMismatch);
            }
            staged_fund_ledger = Some(value);
        } else {
            return Err(ResolutionError::ProofSetMismatch);
        }
    }

    Ok(VerifiedAuthorizedConfigV1 {
        parent,
        current_terminal,
        candidate: candidate.clone(),
        staged_fund_profile,
        staged_fund_ledger,
    })
}
