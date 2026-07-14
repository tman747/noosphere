//! Fail-closed WWM route planning sidecar.
//!
//! This crate selects independently controlled ODoH/OHTTP, onion/MASQUE,
//! deep-mix, or remote-browser routes from signed descriptors. It never turns
//! a failed private request into a direct request. Network protocol engines are
//! replaceable sidecars and remain disabled until E-WWM-08/09 evidence passes.

#![forbid(unsafe_code)]

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];
pub const MAX_ROUTE_DESCRIPTORS: usize = 4_096;
pub const MAX_ROUTE_HOPS: usize = 8;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const WWM_FAST_PRIVATE_ROUTE_ENABLED: bool = false;
pub const WWM_DEEP_PRIVATE_ROUTE_ENABLED: bool = false;
pub const WWM_ROUTE_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    InvalidDescriptor,
    InvalidSignature,
    DuplicateDescriptor,
    InvalidPolicy,
    InsufficientRoute,
    InsufficientDiversity,
    DirectFallbackForbidden,
    CircuitExpired,
    CircuitFailed,
    InvalidFrame,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RouteRole {
    OdohProxy = 1,
    OhttpRelay = 2,
    OnionIngress = 3,
    OnionMiddle = 4,
    OnionEgress = 5,
    Mix = 6,
    RemoteBrowser = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RouteTransport {
    Odoh = 1,
    Ohttp = 2,
    Masque = 3,
    SphinxMix = 4,
    ConfidentialRender = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LoggingPolicy {
    None = 0,
    AggregateOnly = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDescriptor {
    pub operator_key: Hash32,
    pub role: RouteRole,
    pub transports: Vec<RouteTransport>,
    pub control_cluster: Hash32,
    pub region: u16,
    pub asn: u32,
    pub software_lineage_root: Hash32,
    pub attestation_policy_id: Option<Hash32>,
    pub logging_policy: LoggingPolicy,
    pub retention_seconds: u32,
    pub capacity_requests_per_minute: u32,
    pub price_micro_noos_per_megabyte: u64,
    pub bond_micro_noos: u64,
    pub valid_from_epoch: u64,
    pub expires_epoch: u64,
    pub descriptor_id: Hash32,
    pub signature: [u8; 64],
}

impl RouteDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator: &Keypair,
        role: RouteRole,
        transports: Vec<RouteTransport>,
        control_cluster: Hash32,
        region: u16,
        asn: u32,
        software_lineage_root: Hash32,
        attestation_policy_id: Option<Hash32>,
        logging_policy: LoggingPolicy,
        retention_seconds: u32,
        capacity_requests_per_minute: u32,
        price_micro_noos_per_megabyte: u64,
        bond_micro_noos: u64,
        valid_from_epoch: u64,
        expires_epoch: u64,
    ) -> Result<Self, RouteError> {
        let mut value = Self {
            operator_key: operator.public_key().into_bytes(),
            role,
            transports,
            control_cluster,
            region,
            asn,
            software_lineage_root,
            attestation_policy_id,
            logging_policy,
            retention_seconds,
            capacity_requests_per_minute,
            price_micro_noos_per_megabyte,
            bond_micro_noos,
            valid_from_epoch,
            expires_epoch,
            descriptor_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.descriptor_id = digest(DomainId::WwmRouteDescriptor, &[&body])?;
        value.signature = sign(
            operator,
            DomainId::WwmRouteDescriptor,
            value.descriptor_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RouteError> {
        let body = self.body()?;
        if self.descriptor_id == [0; 32]
            || digest(DomainId::WwmRouteDescriptor, &[&body])? != self.descriptor_id
        {
            return Err(RouteError::InvalidDescriptor);
        }
        verify(
            self.operator_key,
            DomainId::WwmRouteDescriptor,
            self.descriptor_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, RouteError> {
        if self.operator_key == [0; 32]
            || self.control_cluster == [0; 32]
            || self.region == 0
            || self.asn == 0
            || self.software_lineage_root == [0; 32]
            || self.attestation_policy_id == Some([0; 32])
            || self.transports.is_empty()
            || self.transports.len() > 8
            || !strictly_sorted(&self.transports)
            || self.capacity_requests_per_minute == 0
            || self.bond_micro_noos == 0
            || self.valid_from_epoch >= self.expires_epoch
            || (self.logging_policy == LoggingPolicy::None && self.retention_seconds != 0)
            || (self.logging_policy == LoggingPolicy::AggregateOnly && self.retention_seconds == 0)
            || (self.role == RouteRole::RemoteBrowser && self.attestation_policy_id.is_none())
        {
            return Err(RouteError::InvalidDescriptor);
        }
        let mut body = Vec::with_capacity(220);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.operator_key);
        body.push(self.role as u8);
        body.push(u8::try_from(self.transports.len()).map_err(|_| RouteError::ArithmeticOverflow)?);
        for transport in &self.transports {
            body.push(*transport as u8);
        }
        body.extend(self.control_cluster);
        body.extend(self.region.to_le_bytes());
        body.extend(self.asn.to_le_bytes());
        body.extend(self.software_lineage_root);
        match self.attestation_policy_id {
            Some(id) => {
                body.push(1);
                body.extend(id);
            }
            None => body.push(0),
        }
        body.push(self.logging_policy as u8);
        body.extend(self.retention_seconds.to_le_bytes());
        body.extend(self.capacity_requests_per_minute.to_le_bytes());
        body.extend(self.price_micro_noos_per_megabyte.to_le_bytes());
        body.extend(self.bond_micro_noos.to_le_bytes());
        body.extend(self.valid_from_epoch.to_le_bytes());
        body.extend(self.expires_epoch.to_le_bytes());
        Ok(body)
    }

    fn supports(&self, transport: RouteTransport, epoch: u64, minimum_bond: u64) -> bool {
        self.valid_from_epoch <= epoch
            && epoch < self.expires_epoch
            && self.bond_micro_noos >= minimum_bond
            && self.transports.binary_search(&transport).is_ok()
    }
}

#[derive(Debug, Default)]
pub struct RouteRegistry {
    descriptors: BTreeMap<Hash32, RouteDescriptor>,
}

impl RouteRegistry {
    pub fn register(&mut self, descriptor: RouteDescriptor) -> Result<(), RouteError> {
        descriptor.validate()?;
        if self.descriptors.contains_key(&descriptor.descriptor_id)
            || self.descriptors.len() >= MAX_ROUTE_DESCRIPTORS
        {
            return Err(RouteError::DuplicateDescriptor);
        }
        self.descriptors
            .insert(descriptor.descriptor_id, descriptor);
        Ok(())
    }

    #[must_use]
    pub fn active(&self, epoch: u64) -> Vec<&RouteDescriptor> {
        self.descriptors
            .values()
            .filter(|descriptor| {
                descriptor.valid_from_epoch <= epoch && epoch < descriptor.expires_epoch
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouteMode {
    Direct = 0,
    FastPrivateDiscrete = 1,
    FastPrivateCircuit = 2,
    DeepPrivateMix = 3,
    RemoteConfidentialBrowser = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    pub policy_id: Hash32,
    pub mode: RouteMode,
    pub minimum_hops: u8,
    pub minimum_regions: u8,
    pub minimum_asns: u8,
    pub minimum_bond_micro_noos: u64,
    pub frame_bucket_bytes: u32,
    pub maximum_circuit_epochs: u64,
    pub allow_direct_fallback: bool,
    pub require_no_logging: bool,
    pub remote_browser_attestation_policy: Option<Hash32>,
}

impl RoutePolicy {
    pub fn validate(&self) -> Result<(), RouteError> {
        if self.policy_id == [0; 32]
            || self.minimum_hops == 0
            || usize::from(self.minimum_hops) > MAX_ROUTE_HOPS
            || self.minimum_regions == 0
            || self.minimum_regions > self.minimum_hops
            || self.minimum_asns == 0
            || self.minimum_asns > self.minimum_hops
            || self.minimum_bond_micro_noos == 0
            || self.maximum_circuit_epochs == 0
            || self.frame_bucket_bytes == 0
            || usize::try_from(self.frame_bucket_bytes).map_or(true, |bytes| {
                bytes > MAX_FRAME_BYTES || !bytes.is_power_of_two()
            })
            || (self.mode != RouteMode::Direct && self.allow_direct_fallback)
            || (self.mode == RouteMode::Direct && self.minimum_hops != 1)
            || (self.mode == RouteMode::FastPrivateDiscrete && self.minimum_hops != 2)
            || (self.mode == RouteMode::FastPrivateCircuit && self.minimum_hops < 3)
            || (self.mode == RouteMode::DeepPrivateMix && self.minimum_hops < 3)
            || (self.mode == RouteMode::RemoteConfidentialBrowser
                && self.remote_browser_attestation_policy.is_none())
            || self.remote_browser_attestation_policy == Some([0; 32])
        {
            return Err(RouteError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCircuit {
    pub circuit_id: Hash32,
    pub policy_id: Hash32,
    pub mode: RouteMode,
    pub descriptor_ids: Vec<Hash32>,
    pub control_clusters: Vec<Hash32>,
    pub regions: Vec<u16>,
    pub asns: Vec<u32>,
    pub created_epoch: u64,
    pub expires_epoch: u64,
    pub direct_fallback: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn select_route(
    policy: &RoutePolicy,
    registry: &RouteRegistry,
    finalized_randomness: Hash32,
    client_nonce: Hash32,
    epoch: u64,
) -> Result<RouteCircuit, RouteError> {
    policy.validate()?;
    if finalized_randomness == [0; 32] || client_nonce == [0; 32] {
        return Err(RouteError::InvalidPolicy);
    }
    if policy.mode == RouteMode::Direct {
        let circuit_id = digest(
            DomainId::WwmRouteDescriptor,
            &[
                b"DIRECT",
                &policy.policy_id,
                &client_nonce,
                &epoch.to_le_bytes(),
            ],
        )?;
        return Ok(RouteCircuit {
            circuit_id,
            policy_id: policy.policy_id,
            mode: RouteMode::Direct,
            descriptor_ids: Vec::new(),
            control_clusters: Vec::new(),
            regions: Vec::new(),
            asns: Vec::new(),
            created_epoch: epoch,
            expires_epoch: epoch
                .checked_add(policy.maximum_circuit_epochs)
                .ok_or(RouteError::ArithmeticOverflow)?,
            direct_fallback: true,
        });
    }
    if policy.allow_direct_fallback {
        return Err(RouteError::DirectFallbackForbidden);
    }

    let requirements = role_requirements(policy)?;
    let active = registry.active(epoch);
    let mut selected = Vec::new();
    let mut used_descriptors = BTreeSet::new();
    let mut clusters = BTreeSet::new();
    for (role, transport) in requirements {
        let mut candidates = active
            .iter()
            .copied()
            .filter(|descriptor| {
                descriptor.role == role
                    && descriptor.supports(transport, epoch, policy.minimum_bond_micro_noos)
                    && (!policy.require_no_logging
                        || descriptor.logging_policy == LoggingPolicy::None)
                    && !used_descriptors.contains(&descriptor.descriptor_id)
                    && !clusters.contains(&descriptor.control_cluster)
                    && (policy.remote_browser_attestation_policy.is_none()
                        || role != RouteRole::RemoteBrowser
                        || descriptor.attestation_policy_id
                            == policy.remote_browser_attestation_policy)
            })
            .map(|descriptor| {
                let score = digest(
                    DomainId::WwmRouteDescriptor,
                    &[
                        b"SELECT",
                        &finalized_randomness,
                        &client_nonce,
                        &policy.policy_id,
                        &descriptor.descriptor_id,
                    ],
                )?;
                Ok((score, descriptor))
            })
            .collect::<Result<Vec<_>, RouteError>>()?;
        candidates.sort_by_key(|(score, descriptor)| (*score, descriptor.descriptor_id));
        let (_, descriptor) = candidates.first().ok_or(RouteError::InsufficientRoute)?;
        used_descriptors.insert(descriptor.descriptor_id);
        clusters.insert(descriptor.control_cluster);
        selected.push(*descriptor);
    }
    if selected.len() != usize::from(policy.minimum_hops) {
        return Err(RouteError::InsufficientRoute);
    }
    let regions = selected
        .iter()
        .map(|descriptor| descriptor.region)
        .collect::<BTreeSet<_>>();
    let asns = selected
        .iter()
        .map(|descriptor| descriptor.asn)
        .collect::<BTreeSet<_>>();
    if regions.len() < usize::from(policy.minimum_regions)
        || asns.len() < usize::from(policy.minimum_asns)
        || clusters.len() != selected.len()
    {
        return Err(RouteError::InsufficientDiversity);
    }
    let descriptor_ids = selected
        .iter()
        .map(|descriptor| descriptor.descriptor_id)
        .collect::<Vec<_>>();
    let control_clusters = selected
        .iter()
        .map(|descriptor| descriptor.control_cluster)
        .collect::<Vec<_>>();
    let regions = selected
        .iter()
        .map(|descriptor| descriptor.region)
        .collect::<Vec<_>>();
    let asns = selected
        .iter()
        .map(|descriptor| descriptor.asn)
        .collect::<Vec<_>>();
    let expires_epoch = epoch
        .checked_add(policy.maximum_circuit_epochs)
        .ok_or(RouteError::ArithmeticOverflow)?;
    let circuit_id = digest(
        DomainId::WwmRouteDescriptor,
        &[
            b"CIRCUIT",
            &policy.policy_id,
            &client_nonce,
            &epoch.to_le_bytes(),
            &descriptor_ids.concat(),
        ],
    )?;
    Ok(RouteCircuit {
        circuit_id,
        policy_id: policy.policy_id,
        mode: policy.mode,
        descriptor_ids,
        control_clusters,
        regions,
        asns,
        created_epoch: epoch,
        expires_epoch,
        direct_fallback: false,
    })
}

fn role_requirements(policy: &RoutePolicy) -> Result<Vec<(RouteRole, RouteTransport)>, RouteError> {
    let count = usize::from(policy.minimum_hops);
    let values = match policy.mode {
        RouteMode::FastPrivateDiscrete => vec![
            (RouteRole::OdohProxy, RouteTransport::Odoh),
            (RouteRole::OhttpRelay, RouteTransport::Ohttp),
        ],
        RouteMode::FastPrivateCircuit => {
            let mut roles = Vec::with_capacity(count);
            roles.push((RouteRole::OnionIngress, RouteTransport::Masque));
            for _ in 1..count.saturating_sub(1) {
                roles.push((RouteRole::OnionMiddle, RouteTransport::Masque));
            }
            roles.push((RouteRole::OnionEgress, RouteTransport::Masque));
            roles
        }
        RouteMode::DeepPrivateMix => vec![(RouteRole::Mix, RouteTransport::SphinxMix); count],
        RouteMode::RemoteConfidentialBrowser => {
            let mut roles = Vec::with_capacity(count);
            for _ in 1..count {
                roles.push((RouteRole::OnionMiddle, RouteTransport::Masque));
            }
            roles.push((RouteRole::RemoteBrowser, RouteTransport::ConfidentialRender));
            roles
        }
        RouteMode::Direct => return Err(RouteError::InvalidPolicy),
    };
    Ok(values)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    Ready,
    FailedClosed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddedRouteFrame {
    pub circuit_id: Hash32,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

impl PaddedRouteFrame {
    pub fn new(
        circuit: &RouteCircuit,
        policy: &RoutePolicy,
        sequence: u64,
        encrypted_payload: &[u8],
        epoch: u64,
    ) -> Result<Self, RouteError> {
        policy.validate()?;
        if circuit.policy_id != policy.policy_id
            || circuit.mode != policy.mode
            || epoch >= circuit.expires_epoch
            || sequence == 0
            || encrypted_payload.is_empty()
        {
            return Err(RouteError::CircuitExpired);
        }
        let bucket =
            usize::try_from(policy.frame_bucket_bytes).map_err(|_| RouteError::InvalidFrame)?;
        let framed_len = 4_usize
            .checked_add(encrypted_payload.len())
            .ok_or(RouteError::ArithmeticOverflow)?;
        if framed_len > bucket {
            return Err(RouteError::InvalidFrame);
        }
        let mut bytes = Vec::with_capacity(bucket);
        bytes.extend(
            u32::try_from(encrypted_payload.len())
                .map_err(|_| RouteError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        bytes.extend(encrypted_payload);
        bytes.resize(bucket, 0);
        Ok(Self {
            circuit_id: circuit.circuit_id,
            sequence,
            bytes,
        })
    }
}

#[derive(Debug)]
pub struct RouteSidecar {
    pub circuit: RouteCircuit,
    pub status: CircuitStatus,
    next_sequence: u64,
}

impl RouteSidecar {
    #[must_use]
    pub fn new(circuit: RouteCircuit) -> Self {
        Self {
            circuit,
            status: CircuitStatus::Ready,
            next_sequence: 1,
        }
    }

    pub fn frame(
        &mut self,
        policy: &RoutePolicy,
        encrypted_payload: &[u8],
        epoch: u64,
    ) -> Result<PaddedRouteFrame, RouteError> {
        if self.status != CircuitStatus::Ready {
            return Err(RouteError::CircuitFailed);
        }
        if epoch >= self.circuit.expires_epoch {
            self.status = CircuitStatus::Expired;
            return Err(RouteError::CircuitExpired);
        }
        let frame = PaddedRouteFrame::new(
            &self.circuit,
            policy,
            self.next_sequence,
            encrypted_payload,
            epoch,
        )?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RouteError::ArithmeticOverflow)?;
        Ok(frame)
    }

    pub fn fail(&mut self) -> Result<(), RouteError> {
        if self.status != CircuitStatus::Ready {
            return Err(RouteError::CircuitFailed);
        }
        self.status = CircuitStatus::FailedClosed;
        Ok(())
    }

    pub fn attempt_direct_fallback(&self) -> Result<(), RouteError> {
        if self.circuit.mode == RouteMode::Direct {
            Ok(())
        } else {
            Err(RouteError::DirectFallbackForbidden)
        }
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, RouteError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| RouteError::InvalidDescriptor)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], RouteError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| RouteError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), RouteError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| RouteError::InvalidSignature)
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

    fn descriptor(index: u8, role: RouteRole, transport: RouteTransport) -> RouteDescriptor {
        RouteDescriptor::new(
            &Keypair::from_seed([20 + index; 32]),
            role,
            vec![transport],
            h(40 + index),
            u16::from(index) + 1,
            64_500 + u32::from(index),
            h(60 + index),
            (role == RouteRole::RemoteBrowser).then_some(h(90)),
            LoggingPolicy::None,
            0,
            1_000,
            10,
            1_000,
            1,
            100,
        )
        .unwrap()
    }

    fn policy(mode: RouteMode, hops: u8) -> RoutePolicy {
        RoutePolicy {
            policy_id: h(1 + mode as u8),
            mode,
            minimum_hops: hops,
            minimum_regions: hops,
            minimum_asns: hops,
            minimum_bond_micro_noos: 100,
            frame_bucket_bytes: 65_536,
            maximum_circuit_epochs: 5,
            allow_direct_fallback: mode == RouteMode::Direct,
            require_no_logging: true,
            remote_browser_attestation_policy: (mode == RouteMode::RemoteConfidentialBrowser)
                .then_some(h(90)),
        }
    }

    #[test]
    fn fast_discrete_route_uses_two_independent_operators() {
        let mut registry = RouteRegistry::default();
        registry
            .register(descriptor(1, RouteRole::OdohProxy, RouteTransport::Odoh))
            .unwrap();
        registry
            .register(descriptor(2, RouteRole::OhttpRelay, RouteTransport::Ohttp))
            .unwrap();
        let route = select_route(
            &policy(RouteMode::FastPrivateDiscrete, 2),
            &registry,
            h(10),
            h(11),
            2,
        )
        .unwrap();
        assert_eq!(route.descriptor_ids.len(), 2);
        assert_eq!(
            route.control_clusters.iter().collect::<BTreeSet<_>>().len(),
            2
        );
        assert!(!route.direct_fallback);
    }

    #[test]
    fn deep_mix_requires_distinct_control_clusters_and_fixed_frames() {
        let mut registry = RouteRegistry::default();
        for index in 1..=3 {
            registry
                .register(descriptor(index, RouteRole::Mix, RouteTransport::SphinxMix))
                .unwrap();
        }
        let route_policy = policy(RouteMode::DeepPrivateMix, 3);
        let route = select_route(&route_policy, &registry, h(12), h(13), 2).unwrap();
        let mut sidecar = RouteSidecar::new(route);
        let short = sidecar.frame(&route_policy, &[1; 32], 2).unwrap();
        let long = sidecar.frame(&route_policy, &[2; 1_024], 2).unwrap();
        assert_eq!(short.bytes.len(), 65_536);
        assert_eq!(short.bytes.len(), long.bytes.len());
    }

    #[test]
    fn private_failure_never_becomes_direct() {
        let mut registry = RouteRegistry::default();
        registry
            .register(descriptor(1, RouteRole::OdohProxy, RouteTransport::Odoh))
            .unwrap();
        registry
            .register(descriptor(2, RouteRole::OhttpRelay, RouteTransport::Ohttp))
            .unwrap();
        let route_policy = policy(RouteMode::FastPrivateDiscrete, 2);
        let route = select_route(&route_policy, &registry, h(14), h(15), 2).unwrap();
        let mut sidecar = RouteSidecar::new(route);
        sidecar.fail().unwrap();
        assert_eq!(
            sidecar.attempt_direct_fallback(),
            Err(RouteError::DirectFallbackForbidden)
        );
        assert_eq!(
            sidecar.frame(&route_policy, &[1], 2),
            Err(RouteError::CircuitFailed)
        );
    }

    #[test]
    fn route_services_are_disabled_and_non_consensus() {
        assert!(!WWM_FAST_PRIVATE_ROUTE_ENABLED);
        assert!(!WWM_DEEP_PRIVATE_ROUTE_ENABLED);
        assert_eq!(WWM_ROUTE_CONSENSUS_WEIGHT, 0);
    }
}
