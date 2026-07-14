//! Mind Browser origin isolation, encrypted local vault, permission receipts,
//! and reproducible update admission.
//!
//! Native origins include publisher identity and immutable content revision.
//! Vault records are encrypted under per-origin derived keys and cannot be read
//! through a shared path gateway. The maintained custom browser engine remains
//! disabled; the only admitted initial handoff is an explicitly external Tor
//! Browser flow.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub type Hash32 = [u8; 32];
pub const MAX_NATIVE_NAME_BYTES: usize = 253;
pub const MAX_SERVICE_ENDPOINTS: usize = 16;
pub const MAX_VAULT_VALUE_BYTES: usize = 1024 * 1024;
pub const MAX_BUILDERS: usize = 16;
pub const MIN_INDEPENDENT_BUILDERS: usize = 2;
pub const MIND_BROWSER_CUSTOM_ENGINE_ENABLED: bool = false;
pub const MIND_BROWSER_NATIVE_SCHEME_ENABLED: bool = false;
pub const MIND_BROWSER_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserError {
    InvalidName,
    InvalidOrigin,
    InvalidSignature,
    NameExpired,
    NameRevoked,
    InvalidVaultKey,
    InvalidVaultEntry,
    NonceReuse,
    VaultCrypto,
    PermissionDenied,
    InvalidPermission,
    InvalidBuild,
    InsufficientBuilders,
    BuilderRevoked,
    InvalidUpdate,
    UnknownRollback,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MindNameRecord {
    pub name: String,
    pub publisher_key: Hash32,
    pub content_root: Hash32,
    pub version: u64,
    pub service_endpoint_roots: Vec<Hash32>,
    pub valid_from_height: u64,
    pub expires_height: u64,
    pub revoked_at_height: Option<u64>,
    pub record_id: Hash32,
    pub signature: [u8; 64],
}

impl MindNameRecord {
    pub fn new(
        publisher: &Keypair,
        name: String,
        content_root: Hash32,
        version: u64,
        service_endpoint_roots: Vec<Hash32>,
        valid_from_height: u64,
        expires_height: u64,
    ) -> Result<Self, BrowserError> {
        let mut value = Self {
            name,
            publisher_key: publisher.public_key().into_bytes(),
            content_root,
            version,
            service_endpoint_roots,
            valid_from_height,
            expires_height,
            revoked_at_height: None,
            record_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.record_id = digest(DomainId::WwmMindName, &[&body])?;
        value.signature = sign(publisher, DomainId::WwmMindName, value.record_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        let body = self.body()?;
        if self.record_id == [0; 32] || digest(DomainId::WwmMindName, &[&body])? != self.record_id {
            return Err(BrowserError::InvalidName);
        }
        verify(
            self.publisher_key,
            DomainId::WwmMindName,
            self.record_id,
            &body,
            self.signature,
        )
    }

    pub fn resolve(&self, height: u64) -> Result<NativeOrigin, BrowserError> {
        self.validate()?;
        if height < self.valid_from_height || height >= self.expires_height {
            return Err(BrowserError::NameExpired);
        }
        if self
            .revoked_at_height
            .is_some_and(|revoked| revoked <= height)
        {
            return Err(BrowserError::NameRevoked);
        }
        NativeOrigin::new(self.publisher_key, self.content_root, self.version)
    }

    fn body(&self) -> Result<Vec<u8>, BrowserError> {
        if !valid_native_name(&self.name)
            || self.publisher_key == [0; 32]
            || self.content_root == [0; 32]
            || self.version == 0
            || self.service_endpoint_roots.is_empty()
            || self.service_endpoint_roots.len() > MAX_SERVICE_ENDPOINTS
            || !strictly_sorted(&self.service_endpoint_roots)
            || self.service_endpoint_roots.contains(&[0; 32])
            || self.valid_from_height >= self.expires_height
            || self
                .revoked_at_height
                .is_some_and(|height| height < self.valid_from_height)
        {
            return Err(BrowserError::InvalidName);
        }
        let capacity = self
            .service_endpoint_roots
            .len()
            .checked_mul(32)
            .and_then(|value| value.checked_add(self.name.len()))
            .and_then(|value| value.checked_add(180))
            .ok_or(BrowserError::ArithmeticOverflow)?;
        let mut body = Vec::with_capacity(capacity);
        body.extend(1_u16.to_le_bytes());
        let name = self.name.as_bytes();
        body.extend(
            u16::try_from(name.len())
                .map_err(|_| BrowserError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        body.extend(name);
        body.extend(self.publisher_key);
        body.extend(self.content_root);
        body.extend(self.version.to_le_bytes());
        push_hashes(&mut body, &self.service_endpoint_roots)?;
        body.extend(self.valid_from_height.to_le_bytes());
        body.extend(self.expires_height.to_le_bytes());
        match self.revoked_at_height {
            Some(height) => {
                body.push(1);
                body.extend(height.to_le_bytes());
            }
            None => body.push(0),
        }
        Ok(body)
    }
}

fn valid_native_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NATIVE_NAME_BYTES
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeOrigin {
    pub publisher_key_hash: Hash32,
    pub content_root: Hash32,
    pub version: u64,
    pub origin_id: Hash32,
}

impl NativeOrigin {
    pub fn new(
        publisher_key: Hash32,
        content_root: Hash32,
        version: u64,
    ) -> Result<Self, BrowserError> {
        if publisher_key == [0; 32] || content_root == [0; 32] || version == 0 {
            return Err(BrowserError::InvalidOrigin);
        }
        let publisher_key_hash = digest(DomainId::WwmMindName, &[b"PUBLISHER", &publisher_key])?;
        let origin_id = digest(
            DomainId::WwmMindName,
            &[
                b"ORIGIN",
                &publisher_key_hash,
                &content_root,
                &version.to_le_bytes(),
            ],
        )?;
        Ok(Self {
            publisher_key_hash,
            content_root,
            version,
            origin_id,
        })
    }

    #[must_use]
    pub fn security_origin(&self) -> String {
        format!(
            "mind://{}/{}/{}",
            hex(&self.publisher_key_hash),
            hex(&self.content_root),
            self.version
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum VaultPartition {
    Cookies = 1,
    LocalStorage = 2,
    IndexedDb = 3,
    ServiceWorkers = 4,
    Cache = 5,
    TlsState = 6,
    CircuitState = 7,
    QueryHistory = 8,
}

#[derive(Debug, Clone)]
struct VaultEntry {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    expires_at: Option<u64>,
}

#[derive(Debug, Default)]
pub struct OriginVault {
    entries: BTreeMap<(Hash32, VaultPartition, Hash32), VaultEntry>,
    used_nonces: BTreeSet<(Hash32, [u8; 24])>,
}

impl OriginVault {
    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &mut self,
        root_key: &[u8; 32],
        origin: NativeOrigin,
        partition: VaultPartition,
        key_name: &[u8],
        value: &[u8],
        nonce: [u8; 24],
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<(), BrowserError> {
        if *root_key == [0; 32]
            || key_name.is_empty()
            || value.len() > MAX_VAULT_VALUE_BYTES
            || nonce == [0; 24]
            || expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(BrowserError::InvalidVaultEntry);
        }
        if !self.used_nonces.insert((origin.origin_id, nonce)) {
            return Err(BrowserError::NonceReuse);
        }
        let key_name_hash = digest(DomainId::WwmPermissionReceipt, &[b"VAULT-KEY", key_name])?;
        let derived = derive_vault_key(root_key, origin.origin_id, partition, key_name_hash)?;
        let aad = vault_aad(origin.origin_id, partition, key_name_hash, expires_at);
        let ciphertext = XChaCha20Poly1305::new((&derived).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|_| BrowserError::VaultCrypto)?;
        self.entries.insert(
            (origin.origin_id, partition, key_name_hash),
            VaultEntry {
                nonce,
                ciphertext,
                expires_at,
            },
        );
        Ok(())
    }

    pub fn get(
        &mut self,
        root_key: &[u8; 32],
        origin: NativeOrigin,
        partition: VaultPartition,
        key_name: &[u8],
        now: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, BrowserError> {
        if *root_key == [0; 32] || key_name.is_empty() {
            return Err(BrowserError::InvalidVaultKey);
        }
        let key_name_hash = digest(DomainId::WwmPermissionReceipt, &[b"VAULT-KEY", key_name])?;
        let map_key = (origin.origin_id, partition, key_name_hash);
        let Some(entry) = self.entries.get(&map_key) else {
            return Ok(None);
        };
        if entry.expires_at.is_some_and(|expiry| now >= expiry) {
            self.entries.remove(&map_key);
            return Ok(None);
        }
        let derived = derive_vault_key(root_key, origin.origin_id, partition, key_name_hash)?;
        let aad = vault_aad(origin.origin_id, partition, key_name_hash, entry.expires_at);
        let plaintext = XChaCha20Poly1305::new((&derived).into())
            .decrypt(
                XNonce::from_slice(&entry.nonce),
                Payload {
                    msg: &entry.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BrowserError::VaultCrypto)?;
        Ok(Some(Zeroizing::new(plaintext)))
    }

    pub fn delete_origin(&mut self, origin: NativeOrigin) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|(origin_id, _, _), _| *origin_id != origin.origin_id);
        before.saturating_sub(self.entries.len())
    }

    #[must_use]
    pub fn entry_count(&self, origin: NativeOrigin) -> usize {
        self.entries
            .keys()
            .filter(|(origin_id, _, _)| *origin_id == origin.origin_id)
            .count()
    }
}

fn derive_vault_key(
    root_key: &[u8; 32],
    origin_id: Hash32,
    partition: VaultPartition,
    key_name_hash: Hash32,
) -> Result<[u8; 32], BrowserError> {
    if *root_key == [0; 32] {
        return Err(BrowserError::InvalidVaultKey);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(b"NOOS/WWM/BROWSER/VAULT/V1"), root_key);
    let mut info = Vec::with_capacity(65);
    info.extend(origin_id);
    info.push(partition as u8);
    info.extend(key_name_hash);
    let mut output = [0; 32];
    hkdf.expand(&info, &mut output)
        .map_err(|_| BrowserError::InvalidVaultKey)?;
    Ok(output)
}

fn vault_aad(
    origin_id: Hash32,
    partition: VaultPartition,
    key_name_hash: Hash32,
    expires_at: Option<u64>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(75);
    aad.extend(origin_id);
    aad.push(partition as u8);
    aad.extend(key_name_hash);
    match expires_at {
        Some(expiry) => {
            aad.push(1);
            aad.extend(expiry.to_le_bytes());
        }
        None => aad.push(0),
    }
    aad
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BrowserCapability {
    ClipboardRead = 1,
    ClipboardWrite = 2,
    Download = 3,
    Upload = 4,
    Camera = 5,
    Microphone = 6,
    WalletSign = 7,
    ExternalNavigation = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PermissionDecision {
    Deny = 0,
    AllowOnce = 1,
    AllowSession = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionReceipt {
    pub device_key: Hash32,
    pub origin_id: Hash32,
    pub capability: BrowserCapability,
    pub resource_root: Hash32,
    pub decision: PermissionDecision,
    pub user_presence: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl PermissionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device: &Keypair,
        origin: NativeOrigin,
        capability: BrowserCapability,
        resource_root: Hash32,
        decision: PermissionDecision,
        user_presence: bool,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, BrowserError> {
        let mut value = Self {
            device_key: device.public_key().into_bytes(),
            origin_id: origin.origin_id,
            capability,
            resource_root,
            decision,
            user_presence,
            issued_at,
            expires_at,
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.receipt_id = digest(DomainId::WwmPermissionReceipt, &[&body])?;
        value.signature = sign(
            device,
            DomainId::WwmPermissionReceipt,
            value.receipt_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn authorize(
        &self,
        origin: NativeOrigin,
        capability: BrowserCapability,
        resource_root: Hash32,
        now: u64,
        user_present: bool,
    ) -> Result<(), BrowserError> {
        let body = self.body()?;
        verify(
            self.device_key,
            DomainId::WwmPermissionReceipt,
            self.receipt_id,
            &body,
            self.signature,
        )?;
        if digest(DomainId::WwmPermissionReceipt, &[&body])? != self.receipt_id
            || self.origin_id != origin.origin_id
            || self.capability != capability
            || self.resource_root != resource_root
            || self.decision == PermissionDecision::Deny
            || now < self.issued_at
            || now >= self.expires_at
            || (self.user_presence && !user_present)
        {
            return Err(BrowserError::PermissionDenied);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, BrowserError> {
        if self.device_key == [0; 32]
            || self.origin_id == [0; 32]
            || self.resource_root == [0; 32]
            || self.issued_at >= self.expires_at
            || (matches!(
                self.capability,
                BrowserCapability::ClipboardRead
                    | BrowserCapability::Download
                    | BrowserCapability::Upload
                    | BrowserCapability::Camera
                    | BrowserCapability::Microphone
                    | BrowserCapability::WalletSign
                    | BrowserCapability::ExternalNavigation
            ) && self.decision != PermissionDecision::Deny
                && !self.user_presence)
        {
            return Err(BrowserError::InvalidPermission);
        }
        let mut body = Vec::with_capacity(124);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.device_key);
        body.extend(self.origin_id);
        body.push(self.capability as u8);
        body.extend(self.resource_root);
        body.push(self.decision as u8);
        body.push(u8::from(self.user_presence));
        body.extend(self.issued_at.to_le_bytes());
        body.extend(self.expires_at.to_le_bytes());
        Ok(body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BrowserPlatform {
    WindowsX8664 = 1,
    MacosUniversal = 2,
    LinuxX8664 = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderIdentity {
    pub builder_key: Hash32,
    pub control_cluster: Hash32,
    pub toolchain_lineage_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderSignature {
    pub builder_index: u8,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserBuildManifest {
    pub channel: Hash32,
    pub platform: BrowserPlatform,
    pub build_number: u64,
    pub source_root: Hash32,
    pub artifact_root: Hash32,
    pub sbom_root: Hash32,
    pub dependency_lock_root: Hash32,
    pub toolchain_root: Hash32,
    pub transparency_log_root: Hash32,
    pub prior_build_id: Option<Hash32>,
    pub minimum_supported_build: u64,
    pub builders: Vec<BuilderIdentity>,
    pub builder_threshold: u8,
    pub build_id: Hash32,
    pub signatures: Vec<BuilderSignature>,
}

impl BrowserBuildManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel: Hash32,
        platform: BrowserPlatform,
        build_number: u64,
        source_root: Hash32,
        artifact_root: Hash32,
        sbom_root: Hash32,
        dependency_lock_root: Hash32,
        toolchain_root: Hash32,
        transparency_log_root: Hash32,
        prior_build_id: Option<Hash32>,
        minimum_supported_build: u64,
        builders: Vec<BuilderIdentity>,
        builder_threshold: u8,
    ) -> Result<Self, BrowserError> {
        let mut value = Self {
            channel,
            platform,
            build_number,
            source_root,
            artifact_root,
            sbom_root,
            dependency_lock_root,
            toolchain_root,
            transparency_log_root,
            prior_build_id,
            minimum_supported_build,
            builders,
            builder_threshold,
            build_id: [0; 32],
            signatures: Vec::new(),
        };
        let body = value.body()?;
        value.build_id = digest(DomainId::WwmBrowserBuild, &[&body])?;
        Ok(value)
    }

    pub fn add_signature(&mut self, builder: &Keypair) -> Result<(), BrowserError> {
        if self.build_id == [0; 32]
            || digest(DomainId::WwmBrowserBuild, &[&self.body()?])? != self.build_id
        {
            return Err(BrowserError::InvalidBuild);
        }
        let key = builder.public_key().into_bytes();
        let index = self
            .builders
            .binary_search_by_key(&key, |identity| identity.builder_key)
            .map_err(|_| BrowserError::InvalidSignature)?;
        let index = u8::try_from(index).map_err(|_| BrowserError::ArithmeticOverflow)?;
        if self
            .signatures
            .iter()
            .any(|signature| signature.builder_index == index)
        {
            return Err(BrowserError::InvalidSignature);
        }
        let body = self.body()?;
        self.signatures.push(BuilderSignature {
            builder_index: index,
            signature: sign(builder, DomainId::WwmBrowserBuild, self.build_id, &body)?,
        });
        self.signatures
            .sort_by_key(|signature| signature.builder_index);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        let body = self.body()?;
        if self.build_id == [0; 32]
            || digest(DomainId::WwmBrowserBuild, &[&body])? != self.build_id
            || self.signatures.len() < usize::from(self.builder_threshold)
            || !strictly_sorted_by(&self.signatures, |signature| signature.builder_index)
        {
            return Err(BrowserError::InvalidBuild);
        }
        let mut clusters = BTreeSet::new();
        for signature in &self.signatures {
            let builder = self
                .builders
                .get(usize::from(signature.builder_index))
                .ok_or(BrowserError::InvalidSignature)?;
            verify(
                builder.builder_key,
                DomainId::WwmBrowserBuild,
                self.build_id,
                &body,
                signature.signature,
            )?;
            clusters.insert(builder.control_cluster);
        }
        if clusters.len() < usize::from(self.builder_threshold) {
            return Err(BrowserError::InsufficientBuilders);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, BrowserError> {
        let roots = [
            self.channel,
            self.source_root,
            self.artifact_root,
            self.sbom_root,
            self.dependency_lock_root,
            self.toolchain_root,
            self.transparency_log_root,
        ];
        if roots.contains(&[0; 32])
            || self.build_number == 0
            || self.minimum_supported_build == 0
            || self.minimum_supported_build > self.build_number
            || self.prior_build_id == Some([0; 32])
            || self.builders.len() < MIN_INDEPENDENT_BUILDERS
            || self.builders.len() > MAX_BUILDERS
            || usize::from(self.builder_threshold) < MIN_INDEPENDENT_BUILDERS
            || usize::from(self.builder_threshold) > self.builders.len()
            || !strictly_sorted_by(&self.builders, |builder| builder.builder_key)
            || self.builders.iter().any(|builder| {
                builder.builder_key == [0; 32]
                    || builder.control_cluster == [0; 32]
                    || builder.toolchain_lineage_root == [0; 32]
            })
            || self
                .builders
                .iter()
                .map(|builder| builder.control_cluster)
                .collect::<BTreeSet<_>>()
                .len()
                < usize::from(self.builder_threshold)
        {
            return Err(BrowserError::InvalidBuild);
        }
        let capacity = self
            .builders
            .len()
            .checked_mul(96)
            .and_then(|value| value.checked_add(400))
            .ok_or(BrowserError::ArithmeticOverflow)?;
        let mut body = Vec::with_capacity(capacity);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.channel);
        body.push(self.platform as u8);
        body.extend(self.build_number.to_le_bytes());
        for root in roots.into_iter().skip(1) {
            body.extend(root);
        }
        match self.prior_build_id {
            Some(id) => {
                body.push(1);
                body.extend(id);
            }
            None => body.push(0),
        }
        body.extend(self.minimum_supported_build.to_le_bytes());
        body.push(u8::try_from(self.builders.len()).map_err(|_| BrowserError::ArithmeticOverflow)?);
        for builder in &self.builders {
            body.extend(builder.builder_key);
            body.extend(builder.control_cluster);
            body.extend(builder.toolchain_lineage_root);
        }
        body.push(self.builder_threshold);
        Ok(body)
    }
}

#[derive(Debug)]
pub struct BrowserUpdateState {
    pub current: BrowserBuildManifest,
    accepted: BTreeMap<Hash32, BrowserBuildManifest>,
    revoked_builders: BTreeSet<Hash32>,
}

impl BrowserUpdateState {
    pub fn new(genesis: BrowserBuildManifest) -> Result<Self, BrowserError> {
        genesis.validate()?;
        if genesis.prior_build_id.is_some() {
            return Err(BrowserError::InvalidUpdate);
        }
        let mut accepted = BTreeMap::new();
        accepted.insert(genesis.build_id, genesis.clone());
        Ok(Self {
            current: genesis,
            accepted,
            revoked_builders: BTreeSet::new(),
        })
    }

    pub fn revoke_builder(&mut self, builder_key: Hash32) -> Result<(), BrowserError> {
        if builder_key == [0; 32] {
            return Err(BrowserError::BuilderRevoked);
        }
        self.revoked_builders.insert(builder_key);
        Ok(())
    }

    pub fn apply(&mut self, candidate: BrowserBuildManifest) -> Result<(), BrowserError> {
        candidate.validate()?;
        if candidate.channel != self.current.channel
            || candidate.platform != self.current.platform
            || candidate.build_number <= self.current.build_number
            || candidate.prior_build_id != Some(self.current.build_id)
            || candidate.minimum_supported_build > self.current.build_number
            || self.accepted.contains_key(&candidate.build_id)
        {
            return Err(BrowserError::InvalidUpdate);
        }
        let valid_unrevoked = candidate
            .signatures
            .iter()
            .filter_map(|signature| candidate.builders.get(usize::from(signature.builder_index)))
            .filter(|builder| !self.revoked_builders.contains(&builder.builder_key))
            .map(|builder| builder.control_cluster)
            .collect::<BTreeSet<_>>();
        if valid_unrevoked.len() < usize::from(candidate.builder_threshold) {
            return Err(BrowserError::BuilderRevoked);
        }
        self.accepted.insert(candidate.build_id, candidate.clone());
        self.current = candidate;
        Ok(())
    }

    pub fn rollback(&mut self, build_id: Hash32) -> Result<(), BrowserError> {
        let target = self
            .accepted
            .get(&build_id)
            .cloned()
            .ok_or(BrowserError::UnknownRollback)?;
        if target.channel != self.current.channel
            || target.platform != self.current.platform
            || target.build_number >= self.current.build_number
            || target.build_number < self.current.minimum_supported_build
        {
            return Err(BrowserError::InvalidUpdate);
        }
        target.validate()?;
        self.current = target;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserEngineDisposition {
    ExternalTorBrowserHandoff,
    MaintainedCustomEngine,
}

#[must_use]
pub const fn browser_engine_disposition() -> BrowserEngineDisposition {
    if MIND_BROWSER_CUSTOM_ENGINE_ENABLED {
        BrowserEngineDisposition::MaintainedCustomEngine
    } else {
        BrowserEngineDisposition::ExternalTorBrowserHandoff
    }
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), BrowserError> {
    let count = u16::try_from(values.len()).map_err(|_| BrowserError::ArithmeticOverflow)?;
    out.extend(count.to_le_bytes());
    for value in values {
        out.extend(value);
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, K: Ord + Copy>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, BrowserError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| BrowserError::InvalidOrigin)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], BrowserError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| BrowserError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), BrowserError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| BrowserError::InvalidSignature)
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes.len().checked_mul(2).unwrap_or(bytes.len());
    let mut output = String::with_capacity(capacity);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
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

    fn origin(publisher: u8, content: u8, version: u64) -> NativeOrigin {
        NativeOrigin::new(h(publisher), h(content), version).unwrap()
    }

    fn builders() -> (Vec<Keypair>, Vec<BuilderIdentity>) {
        let mut pairs = (0_u8..3)
            .map(|index| {
                let key = Keypair::from_seed([40 + index; 32]);
                let identity = BuilderIdentity {
                    builder_key: key.public_key().into_bytes(),
                    control_cluster: h(50 + index),
                    toolchain_lineage_root: h(60 + index),
                };
                (key, identity)
            })
            .collect::<Vec<_>>();
        pairs.sort_by_key(|(_, identity)| identity.builder_key);
        let identities = pairs.iter().map(|(_, identity)| identity.clone()).collect();
        let keys = pairs.into_iter().map(|(key, _)| key).collect();
        (keys, identities)
    }

    fn build(number: u64, prior: Option<Hash32>, minimum: u64) -> BrowserBuildManifest {
        let (keys, identities) = builders();
        let mut manifest = BrowserBuildManifest::new(
            h(70),
            BrowserPlatform::WindowsX8664,
            number,
            h(71 + number as u8),
            h(81 + number as u8),
            h(91 + number as u8),
            h(101 + number as u8),
            h(111 + number as u8),
            h(121 + number as u8),
            prior,
            minimum,
            identities,
            2,
        )
        .unwrap();
        manifest.add_signature(&keys[0]).unwrap();
        manifest.add_signature(&keys[1]).unwrap();
        manifest
    }

    #[test]
    fn native_origin_partitions_publisher_content_and_version() {
        let first = origin(1, 2, 1);
        assert_ne!(first.origin_id, origin(1, 3, 1).origin_id);
        assert_ne!(first.origin_id, origin(1, 2, 2).origin_id);
        assert_ne!(first.origin_id, origin(2, 2, 1).origin_id);
        assert!(first.security_origin().starts_with("mind://"));
    }

    #[test]
    fn encrypted_vault_never_crosses_origins_or_reuses_nonce() {
        let first = origin(1, 2, 1);
        let second = origin(1, 3, 1);
        let mut vault = OriginVault::default();
        vault
            .put(
                &h(10),
                first,
                VaultPartition::Cookies,
                b"session",
                b"secret",
                [1; 24],
                1,
                Some(10),
            )
            .unwrap();
        assert_eq!(
            vault
                .get(&h(10), first, VaultPartition::Cookies, b"session", 2)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert!(vault
            .get(&h(10), second, VaultPartition::Cookies, b"session", 2)
            .unwrap()
            .is_none());
        assert_eq!(
            vault.put(
                &h(10),
                first,
                VaultPartition::Cookies,
                b"other",
                b"value",
                [1; 24],
                2,
                None
            ),
            Err(BrowserError::NonceReuse)
        );
        assert!(vault
            .get(&h(11), first, VaultPartition::Cookies, b"session", 2)
            .is_err());
        assert!(vault
            .get(&h(10), first, VaultPartition::Cookies, b"session", 10)
            .unwrap()
            .is_none());
    }

    #[test]
    fn permission_receipt_is_exact_origin_resource_and_presence_bound() {
        let device = Keypair::from_seed([20; 32]);
        let first = origin(1, 2, 1);
        let receipt = PermissionReceipt::new(
            &device,
            first,
            BrowserCapability::WalletSign,
            h(30),
            PermissionDecision::AllowOnce,
            true,
            10,
            20,
        )
        .unwrap();
        receipt
            .authorize(first, BrowserCapability::WalletSign, h(30), 11, true)
            .unwrap();
        assert_eq!(
            receipt.authorize(
                origin(1, 2, 2),
                BrowserCapability::WalletSign,
                h(30),
                11,
                true
            ),
            Err(BrowserError::PermissionDenied)
        );
        assert_eq!(
            receipt.authorize(first, BrowserCapability::WalletSign, h(30), 11, false),
            Err(BrowserError::PermissionDenied)
        );
    }

    #[test]
    fn updates_require_two_independent_builders_and_support_bounded_rollback() {
        let genesis = build(1, None, 1);
        let genesis_id = genesis.build_id;
        let mut state = BrowserUpdateState::new(genesis).unwrap();
        let second = build(2, Some(genesis_id), 1);
        state.apply(second).unwrap();
        assert_eq!(state.current.build_number, 2);
        state.rollback(genesis_id).unwrap();
        assert_eq!(state.current.build_number, 1);

        let mut one_signature = build(3, Some(genesis_id), 1);
        one_signature.signatures.pop();
        assert_eq!(one_signature.validate(), Err(BrowserError::InvalidBuild));
    }

    #[test]
    fn custom_engine_and_native_scheme_stay_disabled() {
        assert_eq!(
            browser_engine_disposition(),
            BrowserEngineDisposition::ExternalTorBrowserHandoff
        );
        assert!(!MIND_BROWSER_CUSTOM_ENGINE_ENABLED);
        assert!(!MIND_BROWSER_NATIVE_SCHEME_ENABLED);
        assert_eq!(MIND_BROWSER_CONSENSUS_WEIGHT, 0);
    }
}
