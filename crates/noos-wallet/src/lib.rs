//! NOOS wallet primitives. Every operation that observes or authorizes chain state
//! requires a successful [`IdentityGate`] handshake first.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use ring::{
    aead, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::BTreeSet, num::NonZeroU32};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type Hash32 = [u8; 32];
pub const API_VERSION: u16 = 1;
pub const HARDENED: u32 = 1 << 31;
pub const NOOS_NAMESPACE: u32 = 0x4e4f_4f53;
pub const WALLET_VERSION: u32 = 1;
pub const PURPOSE_SIGN: u32 = 1;
pub const PURPOSE_VIEW: u32 = 2;
pub const PURPOSE_UMBRA: u32 = 3;
pub const PURPOSE_AGENT: u32 = 4;
pub const PURPOSE_RECOVERY: u32 = 5;
pub const WALLET_SALT: &[u8] = b"NOOS/HKDF/WALLET/SALT/V1";
pub const WALLET_INFO: &[u8] = b"NOOS/HKDF/WALLET/V1";
pub const SIGNING_DOMAIN: &[u8] = b"NOOS/WALLET/SIGN/V1";
/// Consensus Ed25519 domain for a Lumen `SignedIntentV1` transaction intent.
///
/// The wallet identity gate still runs before this signature is reachable;
/// the transaction's `chain_id` is already committed by its canonical txid.
pub const LUMEN_TX_SIGNING_DOMAIN: &[u8] = b"NOOS/SIG/TX/V1";
const KEYSTORE_AAD: &[u8] = b"NOOS/WALLET/KEYSTORE/V1";
const KEYSTORE_ROUNDS: u32 = 200_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WalletError {
    #[error("wrong_protocol_identity")]
    WrongProtocolIdentity,
    #[error("api_version_mismatch")]
    ApiVersionMismatch,
    #[error("identity handshake required")]
    HandshakeRequired,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    #[error("keystore authentication failed")]
    KeystoreAuthentication,
    #[error("invalid keystore")]
    InvalidKeystore,
    #[error("TLS certificate pin mismatch")]
    TlsPinMismatch,
    #[error("invalid derivation index")]
    InvalidDerivationIndex,
    #[error("invalid private payment")]
    InvalidPrivatePayment,
    #[error("agent payment policy denied")]
    PaymentPolicyDenied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub api_version: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityGate {
    expected: NodeIdentity,
    verified: bool,
}
impl IdentityGate {
    #[must_use]
    pub fn new(expected: NodeIdentity) -> Self {
        Self {
            expected,
            verified: false,
        }
    }
    pub fn verify(&mut self, actual: NodeIdentity) -> Result<(), WalletError> {
        self.verified = false;
        if actual.chain_id != self.expected.chain_id
            || actual.genesis_hash != self.expected.genesis_hash
        {
            return Err(WalletError::WrongProtocolIdentity);
        }
        if actual.api_version != self.expected.api_version {
            return Err(WalletError::ApiVersionMismatch);
        }
        self.verified = true;
        Ok(())
    }
    pub fn require(&self) -> Result<(), WalletError> {
        if self.verified {
            Ok(())
        } else {
            Err(WalletError::HandshakeRequired)
        }
    }
    #[must_use]
    pub fn expected(&self) -> NodeIdentity {
        self.expected
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionStatus {
    Mempool,
    Included,
    Justified,
    Finalized,
}
impl TransactionStatus {
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Mempool => 0,
            Self::Included => 1,
            Self::Justified => 2,
            Self::Finalized => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Sign,
    View,
    Umbra { suite: u32 },
    Agent,
    Recovery,
}
impl Purpose {
    fn number(self) -> u32 {
        match self {
            Self::Sign => PURPOSE_SIGN,
            Self::View => PURPOSE_VIEW,
            Self::Umbra { .. } => PURPOSE_UMBRA,
            Self::Agent => PURPOSE_AGENT,
            Self::Recovery => PURPOSE_RECOVERY,
        }
    }
    #[must_use]
    pub fn can_spend(self) -> bool {
        matches!(self, Self::Sign)
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AuthorityKey {
    secret: [u8; 32],
    #[zeroize(skip)]
    purpose: Purpose,
    account: u32,
    index: u32,
}
impl AuthorityKey {
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    #[must_use]
    pub fn public_id(&self) -> Hash32 {
        *blake3::hash(&self.secret).as_bytes()
    }
    #[must_use]
    pub fn account(&self) -> u32 {
        self.account
    }
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn into_spending_key(mut self) -> Result<SpendingKey, WalletError> {
        if !self.purpose.can_spend() {
            return Err(WalletError::InvalidDerivationIndex);
        }
        let secret = self.secret;
        self.secret.zeroize();
        Ok(SpendingKey(SigningKey::from_bytes(&secret)))
    }
}

pub struct SpendingKey(SigningKey);
impl SpendingKey {
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    pub fn sign(&self, gate: &IdentityGate, body: &[u8]) -> Result<[u8; 64], WalletError> {
        gate.require()?;
        let id = gate.expected();
        let mut msg = Vec::new();
        msg.extend_from_slice(SIGNING_DOMAIN);
        msg.extend_from_slice(&id.chain_id);
        msg.extend_from_slice(&id.genesis_hash);
        msg.extend_from_slice(&id.api_version.to_le_bytes());
        msg.extend_from_slice(body);
        Ok(self.0.sign(&msg).to_bytes())
    }

    /// Sign a canonical Lumen transaction id for `SignedIntentV1`.
    ///
    /// This is deliberately separate from [`Self::sign`], whose wallet-local
    /// envelope binds genesis and API version for non-consensus wallet data.
    pub fn sign_lumen_transaction(
        &self,
        gate: &IdentityGate,
        txid: &Hash32,
    ) -> Result<[u8; 64], WalletError> {
        gate.require()?;
        let mut msg = Vec::with_capacity(LUMEN_TX_SIGNING_DOMAIN.len().saturating_add(txid.len()));
        msg.extend_from_slice(LUMEN_TX_SIGNING_DOMAIN);
        msg.extend_from_slice(txid);
        Ok(self.0.sign(&msg).to_bytes())
    }
}

fn hardened(n: u32) -> Result<u32, WalletError> {
    if n >= HARDENED {
        Err(WalletError::InvalidDerivationIndex)
    } else {
        Ok(n | HARDENED)
    }
}
pub fn derivation_path(
    purpose: Purpose,
    account: u32,
    index: u32,
) -> Result<Vec<u32>, WalletError> {
    let mut p = vec![
        hardened(NOOS_NAMESPACE)?,
        hardened(WALLET_VERSION)?,
        hardened(purpose.number())?,
    ];
    if let Purpose::Umbra { suite } = purpose {
        p.push(hardened(suite)?);
    }
    p.push(hardened(account)?);
    p.push(hardened(index)?);
    Ok(p)
}
pub fn derive_authority(
    seed: &[u8],
    purpose: Purpose,
    account: u32,
    index: u32,
) -> Result<AuthorityKey, WalletError> {
    let path = derivation_path(purpose, account, index)?;
    let mut info = Vec::new();
    info.extend_from_slice(WALLET_INFO);
    for component in path {
        info.extend_from_slice(&component.to_be_bytes());
    }
    let hk = Hkdf::<Sha256>::new(Some(WALLET_SALT), seed);
    let mut secret = [0u8; 32];
    hk.expand(&info, &mut secret)
        .map_err(|_| WalletError::InvalidDerivationIndex)?;
    Ok(AuthorityKey {
        secret,
        purpose,
        account,
        index,
    })
}

/// BIP-39 seed expansion. The phrase checksum belongs to the importing UI; this
/// consensus-independent core rejects malformed word counts and empty words.
pub fn mnemonic_seed(phrase: &str, passphrase: &str) -> Result<[u8; 64], WalletError> {
    let words = phrase.split(' ').collect::<Vec<_>>();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) || words.iter().any(|w| w.is_empty()) {
        return Err(WalletError::InvalidMnemonic);
    }
    let salt = format!("mnemonic{passphrase}");
    let mut out = [0u8; 64];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(2048).ok_or(WalletError::InvalidMnemonic)?,
        salt.as_bytes(),
        phrase.as_bytes(),
        &mut out,
    );
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    pub version: u16,
    pub rounds: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
impl EncryptedKeystore {
    pub fn seal(secret: &[u8], password: &[u8]) -> Result<Self, WalletError> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill(&mut salt)
            .map_err(|_| WalletError::InvalidKeystore)?;
        rng.fill(&mut nonce)
            .map_err(|_| WalletError::InvalidKeystore)?;
        Self::seal_with(secret, password, salt, nonce)
    }
    pub fn seal_with(
        secret: &[u8],
        password: &[u8],
        salt: [u8; 16],
        nonce: [u8; 12],
    ) -> Result<Self, WalletError> {
        let rounds = NonZeroU32::new(KEYSTORE_ROUNDS).ok_or(WalletError::InvalidKeystore)?;
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            &salt,
            password,
            &mut key,
        );
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| WalletError::InvalidKeystore)?;
        key.zeroize();
        let less = aead::LessSafeKey::new(unbound);
        let mut ciphertext = secret.to_vec();
        less.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(KEYSTORE_AAD),
            &mut ciphertext,
        )
        .map_err(|_| WalletError::InvalidKeystore)?;
        Ok(Self {
            version: 1,
            rounds: KEYSTORE_ROUNDS,
            salt,
            nonce,
            ciphertext,
        })
    }
    pub fn open(&self, password: &[u8]) -> Result<Vec<u8>, WalletError> {
        if self.version != 1
            || self.rounds != KEYSTORE_ROUNDS
            || self.ciphertext.len() < aead::AES_256_GCM.tag_len()
        {
            return Err(WalletError::InvalidKeystore);
        }
        let rounds = NonZeroU32::new(self.rounds).ok_or(WalletError::InvalidKeystore)?;
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            &self.salt,
            password,
            &mut key,
        );
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| WalletError::InvalidKeystore)?;
        key.zeroize();
        let less = aead::LessSafeKey::new(unbound);
        let mut data = self.ciphertext.clone();
        less.open_in_place(
            aead::Nonce::assume_unique_for_key(self.nonce),
            aead::Aad::from(KEYSTORE_AAD),
            &mut data,
        )
        .map(|v| v.to_vec())
        .map_err(|_| WalletError::KeystoreAuthentication)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub id: Hash32,
    pub amount: u128,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub notes: Vec<Note>,
    pub total: u128,
    pub change: u128,
}
pub fn balance(gate: &IdentityGate, notes: &[Note]) -> Result<u128, WalletError> {
    gate.require()?;
    notes.iter().try_fold(0u128, |total, note| {
        total.checked_add(note.amount).ok_or(WalletError::Overflow)
    })
}
pub fn select_notes(
    gate: &IdentityGate,
    notes: &[Note],
    target: u128,
) -> Result<Selection, WalletError> {
    gate.require()?;
    let mut sorted = notes.to_vec();
    sorted.sort_by_key(|n| (n.amount, n.id));
    let mut picked = Vec::new();
    let mut total = 0u128;
    for n in sorted {
        picked.push(n);
        total = total.checked_add(n.amount).ok_or(WalletError::Overflow)?;
        if total >= target {
            break;
        }
    }
    if total < target {
        return Err(WalletError::InsufficientFunds);
    }
    Ok(Selection {
        notes: picked,
        total,
        change: total.checked_sub(target).ok_or(WalletError::Overflow)?,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    pub bytes: u64,
    pub grain_steps: u64,
    pub proof_units: u64,
    pub state_reads: u64,
    pub state_writes: u64,
    pub blob_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePlan {
    pub fee: u128,
    pub total_required: u128,
}
pub fn plan_fee(
    gate: &IdentityGate,
    amount: u128,
    r: Resources,
    prices: Resources,
) -> Result<FeePlan, WalletError> {
    gate.require()?;
    let pairs = [
        (r.bytes, prices.bytes),
        (r.grain_steps, prices.grain_steps),
        (r.proof_units, prices.proof_units),
        (r.state_reads, prices.state_reads),
        (r.state_writes, prices.state_writes),
        (r.blob_bytes, prices.blob_bytes),
    ];
    let fee = pairs.into_iter().try_fold(0u128, |acc, (a, b)| {
        acc.checked_add(
            u128::from(a)
                .checked_mul(u128::from(b))
                .ok_or(WalletError::Overflow)?,
        )
        .ok_or(WalletError::Overflow)
    })?;
    Ok(FeePlan {
        fee,
        total_required: amount.checked_add(fee).ok_or(WalletError::Overflow)?,
    })
}

#[derive(Clone, Debug)]
pub struct TlsPolicy {
    pub dns_name: String,
    pub spki_sha256: BTreeSet<Hash32>,
}
impl TlsPolicy {
    pub fn verify(&self, dns_name: &str, spki: Hash32) -> Result<(), WalletError> {
        if dns_name == self.dns_name && self.spki_sha256.contains(&spki) {
            Ok(())
        } else {
            Err(WalletError::TlsPinMismatch)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedTransaction {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub api_version: u16,
    pub amount: u128,
    pub fee: u128,
    pub inputs: Vec<Hash32>,
    pub change: u128,
}
pub fn construct_transaction(
    gate: &IdentityGate,
    selection: &Selection,
    amount: u128,
    fee: u128,
) -> Result<UnsignedTransaction, WalletError> {
    gate.require()?;
    let required = amount.checked_add(fee).ok_or(WalletError::Overflow)?;
    if selection.total < required {
        return Err(WalletError::InsufficientFunds);
    }
    let id = gate.expected();
    let change = selection
        .total
        .checked_sub(required)
        .ok_or(WalletError::Overflow)?;
    Ok(UnsignedTransaction {
        chain_id: id.chain_id,
        genesis_hash: id.genesis_hash,
        api_version: id.api_version,
        amount,
        fee,
        inputs: selection.notes.iter().map(|n| n.id).collect(),
        change,
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub transaction: UnsignedTransaction,
    pub signature: [u8; 64],
}
pub fn prepare_submission(
    gate: &IdentityGate,
    transaction: UnsignedTransaction,
    signature: [u8; 64],
) -> Result<Submission, WalletError> {
    gate.require()?;
    let expected = gate.expected();
    if transaction.chain_id != expected.chain_id
        || transaction.genesis_hash != expected.genesis_hash
    {
        return Err(WalletError::WrongProtocolIdentity);
    }
    if transaction.api_version != expected.api_version {
        return Err(WalletError::ApiVersionMismatch);
    }
    Ok(Submission {
        transaction,
        signature,
    })
}

pub const MAX_PRIVATE_MEMO_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatePaymentPlan {
    pub stable_asset: Hash32,
    pub amount: u128,
    pub recipient_commitment: Hash32,
    pub memo_commitment: Hash32,
    pub reference_commitment: Hash32,
    pub expiry_height: u64,
    pub payment_kind: u8,
    pub envelope: noos_umbra::stealth::StealthEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedPrivatePayment {
    pub recipient: Hash32,
    pub claim_secret: Hash32,
    pub stable_asset: Hash32,
    pub amount: u128,
    pub reference_commitment: Hash32,
    pub expiry_height: u64,
    pub payment_kind: u8,
    pub memo: Vec<u8>,
}

fn payment_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_private_payment(
    gate: &IdentityGate,
    recipient: Hash32,
    recipient_scan_public: [u8; 32],
    ephemeral_secret: [u8; 32],
    nonce: [u8; 12],
    claim_secret: Hash32,
    stable_asset: Hash32,
    amount: u128,
    reference_commitment: Hash32,
    expiry_height: u64,
    payment_kind: u8,
    memo: &[u8],
) -> Result<PrivatePaymentPlan, WalletError> {
    gate.require()?;
    if recipient == [0; 32]
        || recipient_scan_public == [0; 32]
        || ephemeral_secret == [0; 32]
        || claim_secret == [0; 32]
        || stable_asset == [0; 32]
        || amount == 0
        || expiry_height == 0
        || payment_kind > 3
        || memo.is_empty()
        || memo.len() > MAX_PRIVATE_MEMO_BYTES
    {
        return Err(WalletError::InvalidPrivatePayment);
    }
    let memo_commitment = payment_hash("NOOS/PRIVATE-PAYMENT/MEMO/V1", &[memo]);
    let recipient_commitment = payment_hash(
        "NOOS/PRIVATE-PAYMENT/RECIPIENT/V1",
        &[&recipient, &claim_secret],
    );
    let memo_len = u32::try_from(memo.len()).map_err(|_| WalletError::InvalidPrivatePayment)?;
    let mut note = Vec::with_capacity(158usize.saturating_add(memo.len()));
    note.extend_from_slice(&1u16.to_le_bytes());
    note.extend_from_slice(&recipient);
    note.extend_from_slice(&claim_secret);
    note.extend_from_slice(&stable_asset);
    note.extend_from_slice(&amount.to_le_bytes());
    note.extend_from_slice(&reference_commitment);
    note.extend_from_slice(&expiry_height.to_le_bytes());
    note.push(payment_kind);
    note.extend_from_slice(&memo_len.to_le_bytes());
    note.extend_from_slice(memo);
    let envelope = noos_umbra::stealth::seal(
        &x25519_dalek::PublicKey::from(recipient_scan_public),
        x25519_dalek::StaticSecret::from(ephemeral_secret),
        nonce,
        &note,
    )
    .map_err(|_| WalletError::InvalidPrivatePayment)?;
    Ok(PrivatePaymentPlan {
        stable_asset,
        amount,
        recipient_commitment,
        memo_commitment,
        reference_commitment,
        expiry_height,
        payment_kind,
        envelope,
    })
}

fn payment_take32(note: &[u8], offset: &mut usize) -> Result<Hash32, WalletError> {
    let end = offset
        .checked_add(32)
        .ok_or(WalletError::InvalidPrivatePayment)?;
    let bytes = note
        .get(*offset..end)
        .ok_or(WalletError::InvalidPrivatePayment)?;
    let mut value = [0u8; 32];
    value.copy_from_slice(bytes);
    *offset = end;
    Ok(value)
}

pub fn open_private_payment(
    gate: &IdentityGate,
    scan_secret: [u8; 32],
    plan: &PrivatePaymentPlan,
) -> Result<Option<OpenedPrivatePayment>, WalletError> {
    gate.require()?;
    let outcome = noos_umbra::stealth::scan(
        &x25519_dalek::StaticSecret::from(scan_secret),
        &plan.envelope,
    )
    .map_err(|_| WalletError::InvalidPrivatePayment)?;
    let noos_umbra::stealth::ScanOutcome::Note(note) = outcome else {
        return Ok(None);
    };
    if note.len() < 159 || u16::from_le_bytes([note[0], note[1]]) != 1 {
        return Err(WalletError::InvalidPrivatePayment);
    }
    let mut offset = 2usize;
    let recipient = payment_take32(&note, &mut offset)?;
    let claim_secret = payment_take32(&note, &mut offset)?;
    let stable_asset = payment_take32(&note, &mut offset)?;
    let amount = u128::from_le_bytes(
        note[offset..offset.saturating_add(16)]
            .try_into()
            .map_err(|_| WalletError::InvalidPrivatePayment)?,
    );
    offset = offset.saturating_add(16);
    let reference_commitment = payment_take32(&note, &mut offset)?;
    let expiry_height = u64::from_le_bytes(
        note[offset..offset.saturating_add(8)]
            .try_into()
            .map_err(|_| WalletError::InvalidPrivatePayment)?,
    );
    offset = offset.saturating_add(8);
    let payment_kind = *note.get(offset).ok_or(WalletError::InvalidPrivatePayment)?;
    offset = offset.saturating_add(1);
    let memo_len = u32::from_le_bytes(
        note[offset..offset.saturating_add(4)]
            .try_into()
            .map_err(|_| WalletError::InvalidPrivatePayment)?,
    ) as usize;
    offset = offset.saturating_add(4);
    if note.len() != offset.saturating_add(memo_len)
        || stable_asset != plan.stable_asset
        || amount != plan.amount
        || reference_commitment != plan.reference_commitment
        || expiry_height != plan.expiry_height
        || payment_kind != plan.payment_kind
        || payment_hash("NOOS/PRIVATE-PAYMENT/MEMO/V1", &[&note[offset..]]) != plan.memo_commitment
        || payment_hash(
            "NOOS/PRIVATE-PAYMENT/RECIPIENT/V1",
            &[&recipient, &claim_secret],
        ) != plan.recipient_commitment
    {
        return Err(WalletError::InvalidPrivatePayment);
    }
    Ok(Some(OpenedPrivatePayment {
        recipient,
        claim_secret,
        stable_asset,
        amount,
        reference_commitment,
        expiry_height,
        payment_kind,
        memo: note[offset..].to_vec(),
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentPaymentPolicy {
    pub allowed_stable_assets: BTreeSet<Hash32>,
    pub per_payment_limit: u128,
    pub epoch_spend_limit: u128,
    pub expires_height: u64,
}

impl AgentPaymentPolicy {
    pub fn authorize(
        &self,
        current_height: u64,
        spent_this_epoch: u128,
        plan: &PrivatePaymentPlan,
    ) -> Result<u128, WalletError> {
        let next_spend = spent_this_epoch
            .checked_add(plan.amount)
            .ok_or(WalletError::Overflow)?;
        if current_height > self.expires_height
            || plan.payment_kind != 1
            || !self.allowed_stable_assets.contains(&plan.stable_asset)
            || plan.amount > self.per_payment_limit
            || next_spend > self.epoch_spend_limit
        {
            return Err(WalletError::PaymentPolicyDenied);
        }
        Ok(next_spend)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    fn identity(n: u8) -> NodeIdentity {
        NodeIdentity {
            chain_id: [n; 32],
            genesis_hash: [n + 1; 32],
            api_version: API_VERSION,
        }
    }
    fn gate() -> IdentityGate {
        let mut g = IdentityGate::new(identity(1));
        g.verify(identity(1)).unwrap();
        g
    }
    #[test]
    fn identity_precedes_balance_plan_sign_submit() {
        let g = IdentityGate::new(identity(1));
        assert_eq!(balance(&g, &[]), Err(WalletError::HandshakeRequired));
        assert_eq!(
            select_notes(&g, &[], 0),
            Err(WalletError::HandshakeRequired)
        );
        assert_eq!(
            plan_fee(&g, 0, Resources::default(), Resources::default()),
            Err(WalletError::HandshakeRequired)
        );
        let tx = UnsignedTransaction {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            api_version: 1,
            amount: 0,
            fee: 0,
            inputs: vec![],
            change: 0,
        };
        assert_eq!(
            prepare_submission(&g, tx, [0; 64]),
            Err(WalletError::HandshakeRequired)
        );
    }
    #[test]
    fn wrong_chain_clears_prior_handshake() {
        let mut g = gate();
        assert_eq!(
            g.verify(identity(9)),
            Err(WalletError::WrongProtocolIdentity)
        );
        assert_eq!(g.require(), Err(WalletError::HandshakeRequired));
    }
    #[test]
    fn purposes_are_distinct_and_only_sign_spends() {
        let seed = [7u8; 64];
        let mut ids = BTreeSet::new();
        for p in [
            Purpose::Sign,
            Purpose::View,
            Purpose::Umbra { suite: 1 },
            Purpose::Agent,
            Purpose::Recovery,
        ] {
            let k = derive_authority(&seed, p, 0, 0).unwrap();
            assert!(ids.insert(k.public_id()));
            if p != Purpose::Sign {
                assert_eq!(
                    k.into_spending_key().err(),
                    Some(WalletError::InvalidDerivationIndex)
                );
            }
        }
    }
    #[test]
    fn derivation_is_hardened() {
        for x in derivation_path(Purpose::Umbra { suite: 7 }, 2, 3).unwrap() {
            assert_ne!(x & HARDENED, 0);
        }
    }
    #[test]
    fn mnemonic_matches_bip39_seed_vector() {
        let p="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(hex::encode(mnemonic_seed(p,"TREZOR").unwrap()),"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    }
    #[test]
    fn keystore_authenticates_ciphertext_and_password() {
        let k = EncryptedKeystore::seal_with(b"seed", b"pw", [1; 16], [2; 12]).unwrap();
        assert_eq!(k.open(b"pw").unwrap(), b"seed");
        assert_eq!(k.open(b"bad"), Err(WalletError::KeystoreAuthentication));
        let mut t = k;
        t.ciphertext[0] ^= 1;
        assert_eq!(t.open(b"pw"), Err(WalletError::KeystoreAuthentication));
    }
    #[test]
    fn selection_change_and_fee_are_checked() {
        let g = gate();
        let s = select_notes(
            &g,
            &[
                Note {
                    id: [2; 32],
                    amount: 7,
                },
                Note {
                    id: [1; 32],
                    amount: 5,
                },
            ],
            10,
        )
        .unwrap();
        assert_eq!((s.total, s.change), (12, 2));
        let f = plan_fee(
            &g,
            10,
            Resources {
                bytes: 2,
                ..Default::default()
            },
            Resources {
                bytes: 3,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!((f.fee, f.total_required), (6, 16));
    }
    #[test]
    fn transaction_status_order_is_explicit() {
        assert!(TransactionStatus::Mempool.rank() < TransactionStatus::Included.rank());
        assert!(TransactionStatus::Included.rank() < TransactionStatus::Justified.rank());
        assert!(TransactionStatus::Justified.rank() < TransactionStatus::Finalized.rank());
    }
    #[test]
    fn signing_requires_identity_and_binds_it() {
        let key = derive_authority(&[3; 64], Purpose::Sign, 0, 0)
            .unwrap()
            .into_spending_key()
            .unwrap();
        let locked = IdentityGate::new(identity(1));
        assert_eq!(
            key.sign(&locked, b"tx"),
            Err(WalletError::HandshakeRequired)
        );
        let a = key.sign(&gate(), b"tx").unwrap();
        let mut other = IdentityGate::new(identity(2));
        other.verify(identity(2)).unwrap();
        assert_ne!(a, key.sign(&other, b"tx").unwrap());
    }

    #[test]
    fn lumen_signing_uses_the_consensus_transaction_domain() {
        let key = derive_authority(&[3; 64], Purpose::Sign, 0, 0)
            .unwrap()
            .into_spending_key()
            .unwrap();
        let txid = [9; 32];
        let locked = IdentityGate::new(identity(1));
        assert_eq!(
            key.sign_lumen_transaction(&locked, &txid),
            Err(WalletError::HandshakeRequired)
        );
        let signature = ed25519_dalek::Signature::from_bytes(
            &key.sign_lumen_transaction(&gate(), &txid).unwrap(),
        );
        let mut message = Vec::from(LUMEN_TX_SIGNING_DOMAIN);
        message.extend_from_slice(&txid);
        key.0
            .verifying_key()
            .verify_strict(&message, &signature)
            .unwrap();
    }
    #[test]
    fn tls_requires_name_and_pin() {
        let p = TlsPolicy {
            dns_name: "rpc.noos.network".into(),
            spki_sha256: [[8; 32]].into(),
        };
        assert!(p.verify("rpc.noos.network", [8; 32]).is_ok());
        assert_eq!(
            p.verify("evil.invalid", [8; 32]),
            Err(WalletError::TlsPinMismatch)
        );
    }
    #[test]
    fn submission_rechecks_transaction_identity() {
        let mut tx = UnsignedTransaction {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            api_version: 1,
            amount: 0,
            fee: 0,
            inputs: vec![],
            change: 0,
        };
        assert!(prepare_submission(&gate(), tx.clone(), [0; 64]).is_ok());
        tx.chain_id = [9; 32];
        assert_eq!(
            prepare_submission(&gate(), tx, [0; 64]),
            Err(WalletError::WrongProtocolIdentity)
        );
    }
    #[test]
    fn odr_wallet_001_exact_vectors() {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/wallet/derivation-v1.json"
        ))
        .unwrap();
        let cases = doc["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 30);
        for case in cases {
            let purpose = match case["purpose"].as_str().unwrap() {
                "sign" => Purpose::Sign,
                "view" => Purpose::View,
                "umbra" => Purpose::Umbra {
                    suite: case["suite"].as_u64().unwrap() as u32,
                },
                "agent" => Purpose::Agent,
                "recovery" => Purpose::Recovery,
                _ => panic!("unknown purpose"),
            };
            let seed = hex::decode(case["seed"].as_str().unwrap()).unwrap();
            let key = derive_authority(
                &seed,
                purpose,
                case["account"].as_u64().unwrap() as u32,
                case["index"].as_u64().unwrap() as u32,
            )
            .unwrap();
            assert_eq!(
                hex::encode(key.secret),
                case["derived_secret"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            let bytes: Vec<u8> = derivation_path(
                purpose,
                case["account"].as_u64().unwrap() as u32,
                case["index"].as_u64().unwrap() as u32,
            )
            .unwrap()
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect();
            assert_eq!(hex::encode(bytes), case["bytes"].as_str().unwrap());
        }
    }

    #[test]
    fn private_stable_payment_opens_only_for_recipient_scan_key() {
        let scan_secret = [0x31; 32];
        let scan_public =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(scan_secret))
                .as_bytes();
        let plan = prepare_private_payment(
            &gate(),
            [0x41; 32],
            scan_public,
            [0x51; 32],
            [0x61; 12],
            [0x71; 32],
            [0x81; 32],
            42_000,
            [0x91; 32],
            500,
            1,
            b"agent inference invoice 7",
        )
        .unwrap();
        let opened = open_private_payment(&gate(), scan_secret, &plan)
            .unwrap()
            .unwrap();
        assert_eq!(opened.recipient, [0x41; 32]);
        assert_eq!(opened.claim_secret, [0x71; 32]);
        assert_eq!(opened.memo, b"agent inference invoice 7");
        assert_ne!(plan.memo_commitment, [0; 32]);
        assert_ne!(plan.recipient_commitment, [0; 32]);
        assert!(
            open_private_payment(&gate(), [0x32; 32], &plan).is_err()
                || open_private_payment(&gate(), [0x32; 32], &plan).unwrap() == None
        );
    }

    #[test]
    fn agent_payment_policy_caps_assets_amounts_and_epoch_spend() {
        let stable = [0x81; 32];
        let scan_secret = [0x31; 32];
        let scan_public =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(scan_secret))
                .as_bytes();
        let plan = prepare_private_payment(
            &gate(),
            [0x41; 32],
            scan_public,
            [0x51; 32],
            [0x61; 12],
            [0x71; 32],
            stable,
            42_000,
            [0x91; 32],
            500,
            1,
            b"bounded agent payment",
        )
        .unwrap();
        let policy = AgentPaymentPolicy {
            allowed_stable_assets: BTreeSet::from([stable]),
            per_payment_limit: 50_000,
            epoch_spend_limit: 100_000,
            expires_height: 600,
        };
        assert_eq!(policy.authorize(400, 20_000, &plan), Ok(62_000));
        assert_eq!(
            policy.authorize(400, 60_000, &plan),
            Err(WalletError::PaymentPolicyDenied)
        );
        assert_eq!(
            policy.authorize(601, 0, &plan),
            Err(WalletError::PaymentPolicyDenied)
        );
    }
}
