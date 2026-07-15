use noos_codec::NoosEncode;
use noos_lumen::objects::{BoundedBytes, BoundedList, OptionalHash32};
use noos_lumen::wwm::{
    cutover_body_root, runway_body_root, ArtifactDescriptorV1, AvailabilityCertificateV2,
    AvailabilityPolicyV2, CapabilityProfileV1, CapabilitySetV1, CapabilityStatus,
    CustodianCapabilitySetV1, CustodianProfileV2, ExecutionProfileV1, FeePolicyV1, ModelCapsuleV2,
    QueryPolicyV1, RegistryEpochVectorV1, ServiceDirectoryV1, ServingAliasTransitionV1,
    SignatureEntryV1, TestnetModelRegistrationV1, WwmAuthorizedConfigV1, WwmControlMode,
    WwmControlStateV1,
};

use crate::{Hash32, NodeError};

const BONSAI_BYTES: u64 = 3_803_452_480;
const BONSAI_RUNTIME_COMMIT: &[u8] = b"62061f91088281e65071cc38c5f69ee95c39f14e";
const BONSAI_ALIAS: &[u8] = b"bonsai-q1";
const LOCAL_RUNTIME_ENDPOINT: &[u8] = b"http://127.0.0.1:18768/v1";
const FIXTURE_SIGNATURE: &[u8] = b"TESTNET_FIXTURE_ONLY";

fn invalid(message: &str) -> NodeError {
    NodeError::Config(format!("invalid frozen Bonsai fixture: {message}"))
}

fn hex32(value: &str) -> Result<Hash32, NodeError> {
    if value.len() != 64 {
        return Err(invalid("hash length"));
    }
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        };
        let high = nibble(pair[0]).ok_or_else(|| invalid("hash digit"))?;
        let low = nibble(pair[1]).ok_or_else(|| invalid("hash digit"))?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn fixture_hash(label: &[u8], index: u32) -> Hash32 {
    noos_lumen::domain_hash(
        "NOOS/WWM/TESTNET-FIXTURE/V1",
        &[label, &index.to_le_bytes()],
    )
}

fn marker_signature() -> BoundedBytes<96> {
    BoundedBytes::new(FIXTURE_SIGNATURE.to_vec()).unwrap_or_default()
}

fn executor_profiles(runtime_root: Hash32) -> Option<BoundedList<CapabilityProfileV1, 32>> {
    let mut entries = (0_u32..8)
        .map(|index| CapabilityProfileV1 {
            profile_id: fixture_hash(b"executor-profile", index),
            status: CapabilityStatus::Active,
            beneficial_control_root: fixture_hash(b"executor-control", index),
            region_id: fixture_hash(b"region", index % 4),
            asn: 64_512 + index,
            provider_root: fixture_hash(b"executor-provider", index),
            software_lineage_root: runtime_root,
            attestation_epoch: 1,
            attestation_expiry: u64::MAX,
            capability_bitmap: 1,
            selection_weight: 1,
            endpoint_root: fixture_hash(b"executor-endpoint", index),
            staging_bytes: 4 * 1024 * 1024 * 1024,
            capacity_bytes: 8 * 1024 * 1024 * 1024,
            headroom_bytes: 2 * 1024 * 1024 * 1024,
            operator_id: fixture_hash(b"executor-operator", index),
            signing_key: fixture_hash(b"executor-signing-key", index),
            reviewer_id: fixture_hash(b"fixture-reviewer", index),
            reviewer_signature: marker_signature(),
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|profile| profile.profile_id);
    BoundedList::new(entries)
}

fn custodian_profiles(runtime_root: Hash32) -> Option<BoundedList<CustodianProfileV2, 32>> {
    let mut entries = (0_u32..12)
        .map(|index| CustodianProfileV2 {
            profile_id: fixture_hash(b"custodian-profile", index),
            status: CapabilityStatus::Active,
            beneficial_control_root: fixture_hash(b"custodian-control", index),
            region_id: fixture_hash(b"region", index % 4),
            asn: 65_000 + index,
            provider_root: fixture_hash(b"custodian-provider", index % 6),
            software_lineage_root: runtime_root,
            attestation_epoch: 1,
            attestation_expiry: u64::MAX,
            capability_bitmap: 1,
            selection_weight: 1,
            endpoint_root: fixture_hash(b"custodian-endpoint", index),
            staging_bytes: 512 * 1024 * 1024,
            capacity_bytes: 2 * 1024 * 1024 * 1024,
            headroom_bytes: 512 * 1024 * 1024,
            operator_id: fixture_hash(b"custodian-operator", index),
            signing_key: fixture_hash(b"custodian-signing-key", index),
            reviewer_id: fixture_hash(b"fixture-reviewer", index + 8),
            reviewer_signature: marker_signature(),
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|profile| profile.profile_id);
    BoundedList::new(entries)
}

pub(crate) fn registration(
    fund_profile_id: Hash32,
) -> Result<TestnetModelRegistrationV1, NodeError> {
    let published_sha256 =
        hex32("17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0")?;
    let payload_root = hex32("d9fd68fd5b262b0b3672f71c633956c93228e6e3f331ed92ef40e2647de475f7")?;
    let manifest_root = hex32("80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7")?;
    let metadata_root = hex32("0cc47f6379c069e745986bd95c696d78f51d5d4c0f3510f7f3cc5aa1d8311a8f")?;
    let tensor_table_root =
        hex32("ebfc159935469c3c8d40c7ea52dfac26dd996408f70ef36ef981a7dc07b9ee24")?;
    let tokenizer_root = hex32("58f310f0412514cea1a31757c9cc9714666b64fb67127914ab08554c4e0b4d56")?;
    let template_root = hex32("7ccfac375b7121adfb8c35763b183a7707bb071bd1abbd76128986b16c3b4d33")?;
    let license_root = hex32("69849221bfb90053de2134ef5e6d540287b4b98062326492f1f96f5da685524b")?;
    let rights_root = hex32("cef33f95425f9802de78b7b22db0faca84d2216661432a9afcf9620949c21f7e")?;
    let readme_root = hex32("11d03fc8a0b969fa6df837e23b613bfe34fef2283649b8e4d0aea496040a549c")?;
    let runtime_exe = hex32("d09e9f62e2bfc20af43f47dac8adddae47de25ae7678702f109faaa03dfe8a56")?;
    let runtime_impl = hex32("b1708e3878a9b7b92753acb45b4981d340372313dd9310e656b259638c5a6dd1")?;
    let llama_library = hex32("9feb0af2a625b6789cdd94b378132e2267d19bcea951f2efbe36f15aa114e4cd")?;
    let hip_backend = hex32("b81d95e240a46da13ccbb1f71e2bf6c2f74e347c2aa3c9638073454b1b6eac65")?;
    let hip_archive = hex32("9b225a990bcde6022b94741866d67d08d1239080954bd43169a74a75c911ca95")?;

    let runtime_root = noos_lumen::domain_hash(
        "NOOS/WWM/RUNTIME/V1",
        &[b"PrismML-Eng/llama.cpp", BONSAI_RUNTIME_COMMIT],
    );
    let build_root = noos_lumen::domain_hash(
        "NOOS/WWM/BUILD/V1",
        &[&runtime_exe, &runtime_impl, &llama_library, &hip_backend],
    );
    let sbom_root =
        noos_lumen::domain_hash("NOOS/WWM/SBOM/V1", &[BONSAI_RUNTIME_COMMIT, &hip_archive]);
    let provenance_root = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-PROVENANCE/V1",
        &[
            b"prism-ml/Bonsai-27B-gguf",
            b"0cf7e3d21581b169b4df1de8bf01316000e2fbb7",
            &metadata_root,
            &readme_root,
        ],
    );
    let artifact_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-ARTIFACT-ID/V1",
        &[
            &published_sha256,
            &BONSAI_BYTES.to_le_bytes(),
            &payload_root,
            &manifest_root,
        ],
    );
    let assignment_root = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-ASSIGNMENT/V1",
        &[&artifact_id, &manifest_root],
    );
    let geometry_root = noos_lumen::domain_hash(
        "NOOS/WWM/ARTIFACT-GEOMETRY/V1",
        &[
            &12_u8.to_le_bytes(),
            &8_u8.to_le_bytes(),
            &1_047_552_u32.to_le_bytes(),
            &454_u32.to_le_bytes(),
        ],
    );
    let availability_policy_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-AVAILABILITY-POLICY-ID/V2",
        &[
            &artifact_id,
            &manifest_root,
            &assignment_root,
            &geometry_root,
        ],
    );
    let capsule_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-CAPSULE-ID/V2",
        &[
            &artifact_id,
            &manifest_root,
            &tensor_table_root,
            &tokenizer_root,
            &template_root,
            &runtime_root,
            &build_root,
        ],
    );
    let execution_profile_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-EXECUTION-PROFILE-ID/V1",
        &[&capsule_id, &runtime_root, &build_root],
    );
    let query_policy_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-QUERY-POLICY-ID/V1",
        &[&capsule_id, b"TEXT_ONLY_DETERMINISTIC"],
    );
    let fee_policy_id =
        noos_lumen::domain_hash("NOOS/WWM/BONSAI-FEE-POLICY-ID/V1", &[b"TESTNET_ZERO_FEE"]);
    let service_directory_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-SERVICE-DIRECTORY-ID/V1",
        &[LOCAL_RUNTIME_ENDPOINT],
    );

    let executor_entries =
        executor_profiles(runtime_root).ok_or_else(|| invalid("executor profiles exceed bound"))?;
    let executor_set_id = noos_lumen::domain_hash(
        "NOOS/WWM/CAPABILITY-SET/V1",
        &[
            &[0; 32],
            &1_u64.to_le_bytes(),
            &executor_entries.encode_canonical(),
        ],
    );
    let executor_set = CapabilitySetV1 {
        set_id: executor_set_id,
        prior_set_id: [0; 32],
        epoch: 1,
        entries: executor_entries,
    };
    let custodian_entries = custodian_profiles(runtime_root)
        .ok_or_else(|| invalid("custodian profiles exceed bound"))?;
    let custodian_set_id = noos_lumen::domain_hash(
        "NOOS/WWM/CUSTODIAN-CAPABILITY-SET/V1",
        &[
            &[0; 32],
            &1_u64.to_le_bytes(),
            &custodian_entries.encode_canonical(),
        ],
    );
    let custodian_set = CustodianCapabilitySetV1 {
        set_id: custodian_set_id,
        prior_set_id: [0; 32],
        epoch: 1,
        entries: custodian_entries,
    };
    let executor_ids = executor_set
        .entries
        .iter()
        .map(|profile| profile.profile_id)
        .collect::<Vec<_>>();
    let custodian_ids = custodian_set
        .entries
        .iter()
        .map(|profile| profile.profile_id)
        .collect::<Vec<_>>();

    let artifact = ArtifactDescriptorV1 {
        artifact_id,
        media_type: 1,
        source_bytes: BONSAI_BYTES,
        payload_root,
        published_sha256,
        manifest_root,
        codec_profile_id: 1,
        stripe_count: 454,
        license_root,
        rights_root,
        provenance_root,
        publisher_key: fixture_hash(b"publisher-key", 0),
        publisher_height: 0,
        signatures: BoundedList::default(),
    };
    let availability_policy = AvailabilityPolicyV2 {
        policy_id: availability_policy_id,
        artifact_id,
        manifest_root,
        assignment_root,
        geometry_root,
        position_count: 12,
        reconstruction_threshold: 8,
        schedulable_minimum: 9,
        required_regions: 4,
        max_positions_per_region: 3,
        max_positions_per_asn: 2,
        max_positions_per_provider: 3,
        challenge_period: 64,
        response_deadline: 16,
        max_probe_age: 128,
        repair_horizon: 256,
        evidence_retention_horizon: 512,
        samples_per_challenge: 8,
        verifier_sample_size: 8,
        verifier_threshold: 5,
        verifier_capability_bitmap: 1,
        reconstructor_sample_size: 5,
        reconstructor_threshold: 3,
        policy_start_height: 0,
        policy_end_height: u64::MAX,
    };
    let execution_profile = ExecutionProfileV1 {
        profile_id: execution_profile_id,
        capsule_id,
        runtime_root,
        tokenizer_root,
        template_root,
        max_context_tokens: 4096,
        max_output_tokens: 512,
        temperature_milli: 0,
        top_p_milli: 1000,
        top_k: 0,
        tie_rule: 0,
        seed_required: 1,
        attachments_allowed: 0,
    };
    let query_policy = QueryPolicyV1 {
        policy_id: query_policy_id,
        capsule_id,
        max_input_tokens: 3584,
        max_output_tokens: 512,
        max_total_tokens: 4096,
        max_deadline_blocks: 64,
        permitted_evidence_tiers: 1,
        privacy_mode: 0,
        attachments_allowed: 0,
        policy_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-QUERY-POLICY/V1",
            &[b"TEXT_ONLY;LOCAL_VERIFIED;NO_ATTACHMENTS;NO_NETWORK"],
        ),
    };
    let capsule = ModelCapsuleV2 {
        capsule_id,
        artifact_id,
        payload_root,
        manifest_root,
        weight_manifest_root: tensor_table_root,
        tokenizer_root,
        template_root,
        runtime_root,
        build_root,
        sbom_root,
        execution_profile_ids: BoundedList::new(vec![execution_profile_id])
            .ok_or_else(|| invalid("execution profile list"))?,
        query_policy_id,
        availability_policy_id,
        license_root,
        rights_root,
        provenance_root,
        lifecycle: 0,
        rollback_capsule_id: OptionalHash32(None),
        publisher_threshold: 0,
        publisher_signatures: BoundedList::default(),
    };
    let fee_policy = FeePolicyV1 {
        policy_id: fee_policy_id,
        quote_asset: noos_lumen::state::NOOS_ASSET,
        base_fee: 0,
        input_token_fee: 0,
        output_token_fee: 0,
        maximum_fee: 0,
        refund_policy_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-REFUND-POLICY/V1",
            &[b"TESTNET_LOCAL_ONLY_NO_SETTLEMENT"],
        ),
        authority_epoch: 1,
        signature: marker_signature(),
    };
    let endpoint = BoundedBytes::new(LOCAL_RUNTIME_ENDPOINT.to_vec())
        .ok_or_else(|| invalid("service endpoint"))?;
    let service_directory = ServiceDirectoryV1 {
        directory_id: service_directory_id,
        epoch: 1,
        endpoint_records: BoundedList::new(vec![endpoint])
            .ok_or_else(|| invalid("service endpoint list"))?,
        tls_key_root: fixture_hash(b"local-tls-key", 0),
        signing_key_root: fixture_hash(b"local-service-signing-key", 0),
        not_before_height: 0,
        not_after_height: u64::MAX,
        authority_epoch: 1,
        signatures: BoundedList::default(),
    };

    let selected_verifiers =
        BoundedList::new(executor_ids.clone()).ok_or_else(|| invalid("selected verifier list"))?;
    let signer_ids = BoundedList::new(executor_ids[..5].to_vec())
        .ok_or_else(|| invalid("certificate signer list"))?;
    let certificate_signatures = BoundedList::new(
        executor_ids[..5]
            .iter()
            .copied()
            .map(|signer_id| SignatureEntryV1 {
                signer_id,
                signature: marker_signature(),
            })
            .collect(),
    )
    .ok_or_else(|| invalid("certificate signature list"))?;
    let certificate_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-AVAILABILITY-CERTIFICATE-ID/V2",
        &[
            &availability_policy_id,
            &executor_set_id,
            &custodian_set_id,
            &manifest_root,
        ],
    );
    let availability_certificate = AvailabilityCertificateV2 {
        certificate_id,
        policy_id: availability_policy_id,
        artifact_id,
        custodian_set_id,
        custodian_set_root: noos_lumen::domain_hash(
            "NOOS/WWM/CUSTODIAN-CAPABILITY-SET-ROOT/V1",
            &[&custodian_set.encode_canonical()],
        ),
        custodian_set_epoch: custodian_set.epoch,
        executor_set_id,
        executor_set_root: noos_lumen::domain_hash(
            "NOOS/WWM/CAPABILITY-SET-ROOT/V1",
            &[&executor_set.encode_canonical()],
        ),
        executor_set_epoch: executor_set.epoch,
        assignment_root,
        diversity_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-TESTNET-DIVERSITY/V1",
            &[&executor_set_id, &custodian_set_id],
        ),
        challenge_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-TESTNET-CHALLENGE/V1",
            &[b"FIXTURE_NOT_PRODUCTION_CUSTODY_EVIDENCE"],
        ),
        selected_verifiers,
        signer_ids,
        result_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-TESTNET-AVAILABILITY-RESULT/V1",
            &[&manifest_root, b"LOCAL_ARTIFACT_PRESENT"],
        ),
        availability_state: 0,
        issued_height: 0,
        valid_until: u64::MAX,
        signatures: certificate_signatures,
    };

    let runway_body = BoundedBytes::new(
        b"TESTNET_LOCAL_ONLY;ZERO_FUNDS;FIXTURE_CUSTODY;PRODUCTION=false".to_vec(),
    )
    .ok_or_else(|| invalid("runway body"))?;
    let mut cutover = Vec::new();
    cutover.extend_from_slice(b"Bonsai-27B-Q1_0.gguf;");
    cutover.extend_from_slice(b"sha256=");
    cutover.extend_from_slice(b"17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0;");
    cutover.extend_from_slice(b"manifest=");
    cutover.extend_from_slice(b"80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7;");
    cutover.extend_from_slice(b"runtime_commit=");
    cutover.extend_from_slice(BONSAI_RUNTIME_COMMIT);
    let cutover_body = BoundedBytes::new(cutover).ok_or_else(|| invalid("cutover body"))?;
    let runway_root = runway_body_root(&runway_body);
    let cutover_root = cutover_body_root(&cutover_body);
    let release_root = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-TESTNET-RELEASE/V1",
        &[
            &capsule_id,
            &artifact_id,
            &runtime_root,
            &build_root,
            &manifest_root,
        ],
    );
    let config_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-AUTHORIZED-CONFIG-ID/V1",
        &[
            &release_root,
            &capsule_id,
            &availability_policy_id,
            &execution_profile_id,
            &query_policy_id,
            &fee_policy_id,
            &fund_profile_id,
            &service_directory_id,
        ],
    );
    let config = WwmAuthorizedConfigV1 {
        config_id,
        parent_config_id: OptionalHash32(None),
        tier: WwmControlMode::Testnet,
        release_root,
        capsule_id,
        artifact_id,
        availability_policy_id,
        execution_profile_id,
        query_policy_id,
        fee_policy_id,
        fund_profile_id,
        service_directory_id,
        executor_allowlist: BoundedList::new(executor_ids)
            .ok_or_else(|| invalid("executor allowlist"))?,
        custodian_allowlist: BoundedList::new(custodian_ids)
            .ok_or_else(|| invalid("custodian allowlist"))?,
        runway_body,
        runway_root,
        cutover_body,
        cutover_root,
        compatibility_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-COMPATIBILITY/V1",
            &[&runtime_root, &tokenizer_root, &template_root],
        ),
        liability_continuity_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-TESTNET-LIABILITY/V1",
            &[&fund_profile_id, b"ZERO_MONEY"],
        ),
        signer_set_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-TESTNET-SIGNER-SET/V1",
            &[&executor_set.encode_canonical()],
        ),
        signer_set_epoch: 1,
        activation_height: 0,
        signatures: BoundedList::default(),
    };
    let transition_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-TESTNET-CONTROL-TRANSITION/V1",
        &[&config_id, &capsule_id],
    );
    let alias_transition_id = noos_lumen::domain_hash(
        "NOOS/WWM/BONSAI-ALIAS-TRANSITION/V1",
        &[BONSAI_ALIAS, &capsule_id],
    );
    let alias = ServingAliasTransitionV1 {
        transition_id: alias_transition_id,
        alias: BoundedBytes::new(BONSAI_ALIAS.to_vec()).ok_or_else(|| invalid("alias"))?,
        prior_transition_id: OptionalHash32(None),
        prior_capsule_id: OptionalHash32(None),
        new_capsule_id: capsule_id,
        expected_control_state: WwmControlMode::Testnet,
        authority_epoch: 1,
        nonce: 0,
        signature: marker_signature(),
    };
    let control = WwmControlStateV1 {
        mode: WwmControlMode::Testnet,
        active_capsule_id: OptionalHash32(Some(capsule_id)),
        last_transition_id: OptionalHash32(Some(transition_id)),
        last_transition_height: 0,
        direct_prior_live_mode: WwmControlMode::Disabled,
        direct_prior_config_id: OptionalHash32(None),
        active_config_id: OptionalHash32(Some(config_id)),
        latest_authorized_config_id: OptionalHash32(Some(config_id)),
        resolution_config_id: OptionalHash32(Some(config_id)),
        release_root,
        promotion_ledger_root: noos_lumen::domain_hash(
            "NOOS/WWM/BONSAI-TESTNET-PROMOTION-LEDGER/V1",
            &[&config_id, b"LOCAL_ONLY"],
        ),
        capsule_id,
        artifact_id,
        availability_policy_id,
        execution_profile_id,
        query_policy_id,
        runway_root,
    };
    let mut registry = RegistryEpochVectorV1 {
        vector_id: [0; 32],
        executor_set_id,
        executor_epoch: executor_set.epoch,
        custodian_set_id,
        custodian_epoch: custodian_set.epoch,
        fee_policy_id,
        fee_epoch: 1,
        fund_profile_id,
        fund_epoch: 0,
        service_directory_id,
        service_epoch: service_directory.epoch,
    };
    registry.vector_id = noos_lumen::domain_hash(
        "NOOS/WWM/REGISTRY-EPOCH-VECTOR/V1",
        &[&registry.encode_canonical()],
    );

    let registration = TestnetModelRegistrationV1 {
        alias,
        control,
        config,
        capsule,
        artifact,
        availability_policy,
        availability_certificate,
        registry,
        executor_set,
        custodian_set,
        execution_profile,
        query_policy,
        fee_policy,
        service_directory,
    };
    Ok(registration)
}
