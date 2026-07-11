use crate::{domain_hash, Hash32};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecoveryPathKind {
    LocalKey = 1,
    ThresholdRecovery = 2,
    PortableBackup = 3,
}
impl TryFrom<u8> for RecoveryPathKind {
    type Error = AccessError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::LocalKey),
            2 => Ok(Self::ThresholdRecovery),
            3 => Ok(Self::PortableBackup),
            _ => Err(AccessError::UnknownPathType),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPlane {
    OffConsensus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPath {
    pub path_id: Hash32,
    pub kind: RecoveryPathKind,
    pub failure_domain: Hash32,
    pub provider: Option<Hash32>,
    pub identity_material_commitment: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReplica {
    pub artifact_id: Hash32,
    pub replica_id: Hash32,
    pub failure_domain: Hash32,
    pub provider: Option<Hash32>,
    pub content_commitment: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableAccessManifest {
    pub manifest_id: Hash32,
    pub identity_id: Hash32,
    pub recovery_paths: Vec<RecoveryPath>,
    pub artifact_replicas: Vec<ArtifactReplica>,
    pub execution_plane: ExecutionPlane,
}
impl PortableAccessManifest {
    #[must_use]
    pub fn derive_id(&self) -> Hash32 {
        let mut paths = self.recovery_paths.clone();
        paths.sort_by_key(|path| path.path_id);
        let mut replicas = self.artifact_replicas.clone();
        replicas.sort_by_key(|replica| replica.replica_id);
        let mut encoded = Vec::new();
        for path in paths {
            encoded.extend_from_slice(&path.path_id);
            encoded.push(path.kind as u8);
            encoded.extend_from_slice(&path.failure_domain);
            encoded.extend_from_slice(&path.provider.unwrap_or([0; 32]));
            encoded.extend_from_slice(&path.identity_material_commitment);
        }
        for replica in replicas {
            encoded.extend_from_slice(&replica.artifact_id);
            encoded.extend_from_slice(&replica.replica_id);
            encoded.extend_from_slice(&replica.failure_domain);
            encoded.extend_from_slice(&replica.provider.unwrap_or([0; 32]));
            encoded.extend_from_slice(&replica.content_commitment);
        }
        domain_hash(
            "NOOS/LOAM/PORTABLE-ACCESS/V1",
            &[&self.identity_id, &encoded, &[self.execution_plane as u8]],
        )
    }

    pub fn validate(&self) -> Result<(), AccessError> {
        let recovery_domains: BTreeSet<_> = self
            .recovery_paths
            .iter()
            .map(|path| path.failure_domain)
            .collect();
        let mut artifacts: BTreeMap<Hash32, (Hash32, BTreeSet<Hash32>)> = BTreeMap::new();
        for replica in &self.artifact_replicas {
            let (commitment, domains) = artifacts
                .entry(replica.artifact_id)
                .or_insert((replica.content_commitment, BTreeSet::new()));
            if *commitment != replica.content_commitment {
                return Err(AccessError::AmbiguousArtifact);
            }
            domains.insert(replica.failure_domain);
        }
        let path_ids: BTreeSet<_> = self
            .recovery_paths
            .iter()
            .map(|path| path.path_id)
            .collect();
        let replica_ids: BTreeSet<_> = self
            .artifact_replicas
            .iter()
            .map(|replica| replica.replica_id)
            .collect();
        if self.manifest_id != self.derive_id()
            || recovery_domains.len() < 3
            || artifacts.is_empty()
            || artifacts.values().any(|(_, domains)| domains.len() < 3)
            || path_ids.len() != self.recovery_paths.len()
            || replica_ids.len() != self.artifact_replicas.len()
        {
            return Err(AccessError::InsufficientIndependentPaths);
        }
        Ok(())
    }

    pub fn recover_and_fetch(
        &self,
        artifact_id: Hash32,
        unavailable_domains: &BTreeSet<Hash32>,
    ) -> Result<AccessRecovery, AccessError> {
        self.validate()?;
        let identity_path = self
            .recovery_paths
            .iter()
            .filter(|path| !unavailable_domains.contains(&path.failure_domain))
            .min_by_key(|path| path.path_id)
            .ok_or(AccessError::IdentityUnavailable)?;
        let replica = self
            .artifact_replicas
            .iter()
            .filter(|replica| {
                replica.artifact_id == artifact_id
                    && !unavailable_domains.contains(&replica.failure_domain)
            })
            .min_by_key(|replica| replica.replica_id)
            .ok_or(AccessError::ArtifactUnavailable)?;
        Ok(AccessRecovery {
            identity_path: identity_path.path_id,
            artifact_replica: replica.replica_id,
            content_commitment: replica.content_commitment,
        })
    }

    #[must_use]
    pub const fn base_chain_continues_during_inference_outage(&self) -> bool {
        matches!(self.execution_plane, ExecutionPlane::OffConsensus)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRecovery {
    pub identity_path: Hash32,
    pub artifact_replica: Hash32,
    pub content_commitment: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    UnknownPathType,
    InsufficientIndependentPaths,
    IdentityUnavailable,
    ArtifactUnavailable,
    AmbiguousArtifact,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]
    use super::*;

    fn h(n: u8) -> Hash32 {
        [n; 32]
    }

    fn manifest() -> PortableAccessManifest {
        let mut manifest = PortableAccessManifest {
            manifest_id: [0; 32],
            identity_id: h(1),
            recovery_paths: (0..3)
                .map(|index| RecoveryPath {
                    path_id: h(10 + index),
                    kind: match index {
                        0 => RecoveryPathKind::LocalKey,
                        1 => RecoveryPathKind::ThresholdRecovery,
                        _ => RecoveryPathKind::PortableBackup,
                    },
                    failure_domain: h(20 + index),
                    provider: (index != 0).then(|| h(30 + index)),
                    identity_material_commitment: h(40 + index),
                })
                .collect(),
            artifact_replicas: (0..3)
                .map(|index| ArtifactReplica {
                    artifact_id: h(2),
                    replica_id: h(50 + index),
                    failure_domain: h(20 + index),
                    provider: (index != 0).then(|| h(30 + index)),
                    content_commitment: h(60),
                })
                .collect(),
            execution_plane: ExecutionPlane::OffConsensus,
        };
        manifest.manifest_id = manifest.derive_id();
        manifest
    }

    #[test]
    fn three_path_partition_drill_recovers_identity_and_artifact() {
        let manifest = manifest();
        for surviving in 0..3u8 {
            let unavailable = (0..3u8)
                .filter(|index| *index != surviving)
                .map(|index| h(20 + index))
                .collect();
            let recovery = manifest.recover_and_fetch(h(2), &unavailable).unwrap();
            assert_eq!(recovery.content_commitment, h(60));
        }
        assert!(manifest.base_chain_continues_during_inference_outage());
    }

    #[test]
    fn single_provider_and_unknown_path_types_fail_closed() {
        let mut manifest = manifest();
        for path in &mut manifest.recovery_paths {
            path.failure_domain = h(99);
        }
        manifest.manifest_id = manifest.derive_id();
        assert_eq!(
            manifest.validate(),
            Err(AccessError::InsufficientIndependentPaths)
        );
        assert_eq!(
            RecoveryPathKind::try_from(99),
            Err(AccessError::UnknownPathType)
        );
    }
}
