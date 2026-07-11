//! Neural Execution Lane v1 consensus objects and deterministic state machine.
//! The lane is application settlement only: it exposes no proposal weight,
//! proofpower, issuance, or base-finality hook.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

pub mod inference;
pub mod lab;
pub mod luts;

pub type Hash32 = [u8; 32];
pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];
pub const CHUNK_TOKENS: usize = 32;
pub const CHUNK_CLAIM_BYTES: usize = 1_634;
pub const FINAL_CHUNK_BASE_BYTES: usize = 483;
pub const TOKEN_CLAIM_BYTES: usize = 292;
pub const MODEL_MANIFEST_BYTES: usize = 240;
pub const PROMPT_JOB_BYTES: usize = 147;
pub const COMMITTEE_SIZE: u8 = 3;
pub const COMMITTEE_QUORUM: u8 = 2;
pub const MOVE_DEADLINE_BLOCKS: u64 = 25;
pub const MIN_CHALLENGE_SECONDS: u64 = 6 * 60 * 60;
pub const PROOFPOWER: u64 = 0;
pub const NEURAL_LANE_ENABLED: bool = false;
pub const REGISTERED_MODEL_ID: u32 = 1;
pub const REGISTERED_NUMERIC_PROFILE_ID: u32 = 1;
pub const REGISTERED_DECODING_PROFILE_ID: u32 = 1;

pub mod domains {
    pub const MANIFEST: &str = "NOOS/NEL/MANIFEST/V1";
    pub const JOB: &str = "NOOS/NEL/JOB/V1";
    pub const STATE: &str = "NOOS/NEL/STATE/V1";
    pub const TOKEN_CLAIM: &str = "NOOS/NEL/TOKEN_CLAIM/V1";
    pub const CHUNK_CLAIM: &str = "NOOS/NEL/CHUNK_CLAIM/V1";
    pub const FINAL_CHUNK_CLAIM: &str = "NOOS/NEL/FINAL_CHUNK_CLAIM/V1";
    pub const ANCHOR_TX: &str = "NOOS/NEL/ANCHOR_TX/V1";
    pub const JOB_RECEIPT: &str = "NOOS/NEL/JOB_RECEIPT/V1";
    pub const EXECUTOR_REG: &str = "NOOS/NEL/EXECUTOR_REG/V1";
    pub const DISPUTE: &str = "NOOS/NEL/DISPUTE/V1";
    pub const BISECT: &str = "NOOS/NEL/BISECT/V1";
    pub const LEAF_RECEIPT: &str = "NOOS/NEL/LEAF_RECEIPT/V1";
    pub const ENVELOPE: &str = "NOOS/NEL/ENVELOPE/V1";
    pub const FREIVALDS: &str = "NOOS/NEL/FREIVALDS/V1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NelError {
    WrongLength,
    TrailingBytes,
    InvalidCount,
    DuplicatePosition,
    ReorderedRecord,
    WrongDomain,
    InvalidSignature,
    DuplicateSigner,
    NonCommitteeSigner,
    UnknownRegistryId,
    DisabledRegistryId,
    ImmutableRegistry,
    UnsupportedMode,
    InvalidBond,
    InvalidExposure,
    InvalidTransition,
    WrongChunkKind,
    AnchorDeadline,
    AvailabilityRequired,
    ClockPaused,
    Deadline,
    WrongMover,
    WrongRound,
    WrongPosition,
    MalformedEnvelope,
    ProofTooLarge,
    InvalidProof,
    ArithmeticOverflow,
    Tombstoned,
    OutstandingClaims,
    UnknownJob,
    UnknownExecutor,
    DisputeExists,
    DisputeNotFound,
}

#[must_use]
pub fn domain_hash(domain: &str, body: &[u8]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    h.update(body);
    *h.finalize().as_bytes()
}

fn take<const N: usize>(input: &[u8], offset: &mut usize) -> Result<[u8; N], NelError> {
    let end = offset.checked_add(N).ok_or(NelError::WrongLength)?;
    let bytes = input.get(*offset..end).ok_or(NelError::WrongLength)?;
    *offset = end;
    bytes.try_into().map_err(|_| NelError::WrongLength)
}
fn u16_at(input: &[u8], o: &mut usize) -> Result<u16, NelError> {
    Ok(u16::from_le_bytes(take(input, o)?))
}
fn u32_at(input: &[u8], o: &mut usize) -> Result<u32, NelError> {
    Ok(u32::from_le_bytes(take(input, o)?))
}
fn u64_at(input: &[u8], o: &mut usize) -> Result<u64, NelError> {
    Ok(u64::from_le_bytes(take(input, o)?))
}
fn finish(input: &[u8], o: usize) -> Result<(), NelError> {
    if o == input.len() {
        Ok(())
    } else {
        Err(NelError::TrailingBytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifest {
    pub architecture_hash: Hash32,
    pub tokenizer_root: Hash32,
    pub weight_root: Hash32,
    pub shard_size: u32,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub numeric_profile_id: Hash32,
    pub circuit_id: Hash32,
    pub reference_interpreter_hash: Hash32,
    pub max_context: u32,
    pub max_generation: u32,
    pub activation_table_root: Hash32,
}
impl ModelManifest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(MODEL_MANIFEST_BYTES);
        v.extend(self.architecture_hash);
        v.extend(self.tokenizer_root);
        v.extend(self.weight_root);
        v.extend(self.shard_size.to_le_bytes());
        v.extend(self.data_shards.to_le_bytes());
        v.extend(self.parity_shards.to_le_bytes());
        v.extend(self.numeric_profile_id);
        v.extend(self.circuit_id);
        v.extend(self.reference_interpreter_hash);
        v.extend(self.max_context.to_le_bytes());
        v.extend(self.max_generation.to_le_bytes());
        v.extend(self.activation_table_root);
        v
    }
    pub fn decode(b: &[u8]) -> Result<Self, NelError> {
        if b.len() != MODEL_MANIFEST_BYTES {
            return Err(NelError::WrongLength);
        }
        let mut o = 0;
        let x = Self {
            architecture_hash: take(b, &mut o)?,
            tokenizer_root: take(b, &mut o)?,
            weight_root: take(b, &mut o)?,
            shard_size: u32_at(b, &mut o)?,
            data_shards: u16_at(b, &mut o)?,
            parity_shards: u16_at(b, &mut o)?,
            numeric_profile_id: take(b, &mut o)?,
            circuit_id: take(b, &mut o)?,
            reference_interpreter_hash: take(b, &mut o)?,
            max_context: u32_at(b, &mut o)?,
            max_generation: u32_at(b, &mut o)?,
            activation_table_root: take(b, &mut o)?,
        };
        finish(b, o)?;
        Ok(x)
    }
    #[must_use]
    pub fn model_id(&self) -> Hash32 {
        domain_hash(domains::MANIFEST, &self.encode())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyProfile {
    P0Open = 0,
    P1Attested = 1,
    P2SealedWitness = 2,
    P3DeepSealed = 3,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptJob {
    pub model_id: Hash32,
    pub prompt_commitment: Hash32,
    pub prompt_blob_ref: Hash32,
    pub privacy_profile: PrivacyProfile,
    pub decoding_profile_id: Hash32,
    pub max_new_tokens: u16,
    pub fee_escrow: u64,
    pub committee_size: u8,
    pub quorum: u8,
    pub bond_class: u16,
    pub challenge_period: u32,
}
impl PromptJob {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PROMPT_JOB_BYTES);
        v.extend(self.model_id);
        v.extend(self.prompt_commitment);
        v.extend(self.prompt_blob_ref);
        v.push(self.privacy_profile as u8);
        v.extend(self.decoding_profile_id);
        v.extend(self.max_new_tokens.to_le_bytes());
        v.extend(self.fee_escrow.to_le_bytes());
        v.push(self.committee_size);
        v.push(self.quorum);
        v.extend(self.bond_class.to_le_bytes());
        v.extend(self.challenge_period.to_le_bytes());
        v
    }
    pub fn decode(b: &[u8]) -> Result<Self, NelError> {
        if b.len() != PROMPT_JOB_BYTES {
            return Err(NelError::WrongLength);
        }
        let mut o = 0;
        let model_id = take(b, &mut o)?;
        let prompt_commitment = take(b, &mut o)?;
        let prompt_blob_ref = take(b, &mut o)?;
        let p = take::<1>(b, &mut o)?[0];
        let privacy_profile = match p {
            0 => PrivacyProfile::P0Open,
            1 => PrivacyProfile::P1Attested,
            2 => PrivacyProfile::P2SealedWitness,
            3 => PrivacyProfile::P3DeepSealed,
            _ => return Err(NelError::UnsupportedMode),
        };
        let x = Self {
            model_id,
            prompt_commitment,
            prompt_blob_ref,
            privacy_profile,
            decoding_profile_id: take(b, &mut o)?,
            max_new_tokens: u16_at(b, &mut o)?,
            fee_escrow: u64_at(b, &mut o)?,
            committee_size: take::<1>(b, &mut o)?[0],
            quorum: take::<1>(b, &mut o)?[0],
            bond_class: u16_at(b, &mut o)?,
            challenge_period: u32_at(b, &mut o)?,
        };
        finish(b, o)?;
        Ok(x)
    }
    pub fn validate_first_activation(
        &self,
        manifest: &ModelManifest,
        challenge_floor_blocks: u32,
    ) -> Result<(), NelError> {
        if self.privacy_profile != PrivacyProfile::P0Open
            || self.prompt_blob_ref == [0; 32]
            || self.committee_size != 3
            || self.quorum != 2
            || self.decoding_profile_id != registered_decoding_hash()
            || self.model_id != manifest.model_id()
            || manifest.circuit_id != [0; 32]
        {
            return Err(NelError::UnsupportedMode);
        }
        if self.max_new_tokens == 0
            || u32::from(self.max_new_tokens) > manifest.max_generation
            || self.challenge_period < challenge_floor_blocks
        {
            return Err(NelError::InvalidCount);
        }
        Ok(())
    }
}
#[must_use]
pub fn registered_decoding_hash() -> Hash32 {
    domain_hash("NOOS/NEL/DECODING/GREEDY-LOWEST-ID/V1", b"")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenStateCommitment {
    pub job_id: Hash32,
    pub model_root: Hash32,
    pub numeric_profile: Hash32,
    pub t: u32,
    pub token_history_root: Hash32,
    pub kv_commitment: Hash32,
    pub rng_cursor: u64,
    pub trace_root: Hash32,
}
impl TokenStateCommitment {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(204);
        v.extend(self.job_id);
        v.extend(self.model_root);
        v.extend(self.numeric_profile);
        v.extend(self.t.to_le_bytes());
        v.extend(self.token_history_root);
        v.extend(self.kv_commitment);
        v.extend(self.rng_cursor.to_le_bytes());
        v.extend(self.trace_root);
        v
    }
    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        domain_hash(domains::STATE, &self.encode())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    pub position: u32,
    pub token_id: u32,
    pub logits_root: Hash32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumSignatures {
    pub first: Signature,
    pub second: Signature,
}
fn verify_sig(key: &PublicKey, domain: &str, body: &[u8], sig: &Signature) -> Result<(), NelError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| NelError::InvalidSignature)?;
    let msg = domain_hash(domain, body);
    key.verify(&msg, &DalekSignature::from_bytes(sig))
        .map_err(|_| NelError::InvalidSignature)
}
pub fn verify_quorum(
    body: &[u8],
    domain: &str,
    sigs: &QuorumSignatures,
    signers: [u8; 2],
    committee: &[PublicKey; 3],
) -> Result<(), NelError> {
    if signers[0] >= signers[1] {
        return Err(NelError::DuplicateSigner);
    }
    if signers[1] >= 3 {
        return Err(NelError::NonCommitteeSigner);
    }
    verify_sig(
        &committee[usize::from(signers[0])],
        domain,
        body,
        &sigs.first,
    )?;
    verify_sig(
        &committee[usize::from(signers[1])],
        domain,
        body,
        &sigs.second,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaim {
    pub s_t: Hash32,
    pub token_id: u32,
    pub logits_commitment: Hash32,
    pub s_next: Hash32,
    pub chunk_trace_root: Hash32,
    pub toploc_commitment: Hash32,
    pub signatures: QuorumSignatures,
}
impl TokenClaim {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TOKEN_CLAIM_BYTES);
        v.extend(self.s_t);
        v.extend(self.token_id.to_le_bytes());
        v.extend(self.logits_commitment);
        v.extend(self.s_next);
        v.extend(self.chunk_trace_root);
        v.extend(self.toploc_commitment);
        v.extend(self.signatures.first);
        v.extend(self.signatures.second);
        v
    }
    pub fn decode(b: &[u8]) -> Result<Self, NelError> {
        if b.len() != TOKEN_CLAIM_BYTES {
            return Err(NelError::WrongLength);
        }
        let mut o = 0;
        let x = Self {
            s_t: take(b, &mut o)?,
            token_id: u32_at(b, &mut o)?,
            logits_commitment: take(b, &mut o)?,
            s_next: take(b, &mut o)?,
            chunk_trace_root: take(b, &mut o)?,
            toploc_commitment: take(b, &mut o)?,
            signatures: QuorumSignatures {
                first: take(b, &mut o)?,
                second: take(b, &mut o)?,
            },
        };
        finish(b, o)?;
        Ok(x)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkClaimV1 {
    pub s_start: Hash32,
    pub s_end: Hash32,
    pub chunk_trace_root: Hash32,
    pub toploc_fingerprint: [u8; 258],
    pub records: [TokenRecord; 32],
    pub signatures: QuorumSignatures,
}
impl ChunkClaimV1 {
    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(CHUNK_CLAIM_BYTES - 128);
        v.extend(self.s_start);
        v.extend(self.s_end);
        v.extend(self.chunk_trace_root);
        v.extend(self.toploc_fingerprint);
        for r in &self.records {
            v.extend(r.token_id.to_le_bytes());
            v.extend(r.logits_root)
        }
        v
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.body_bytes();
        v.extend(self.signatures.first);
        v.extend(self.signatures.second);
        v
    }
    pub fn decode(b: &[u8], start_position: u32) -> Result<Self, NelError> {
        if b.len() != CHUNK_CLAIM_BYTES {
            return Err(NelError::WrongLength);
        }
        let mut o = 0;
        let s_start = take(b, &mut o)?;
        let s_end = take(b, &mut o)?;
        let chunk_trace_root = take(b, &mut o)?;
        let toploc_fingerprint = take(b, &mut o)?;
        let mut records = Vec::with_capacity(32);
        for i in 0..32u32 {
            records.push(TokenRecord {
                position: start_position
                    .checked_add(i)
                    .ok_or(NelError::ArithmeticOverflow)?,
                token_id: u32_at(b, &mut o)?,
                logits_root: take(b, &mut o)?,
            });
        }
        let records: [TokenRecord; 32] = records.try_into().map_err(|_| NelError::InvalidCount)?;
        let x = Self {
            s_start,
            s_end,
            chunk_trace_root,
            toploc_fingerprint,
            records,
            signatures: QuorumSignatures {
                first: take(b, &mut o)?,
                second: take(b, &mut o)?,
            },
        };
        finish(b, o)?;
        Ok(x)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalChunkClaimV1 {
    pub s_start: Hash32,
    pub s_end: Hash32,
    pub chunk_trace_root: Hash32,
    pub token_count: u8,
    pub toploc_fingerprint: [u8; 258],
    pub records: Vec<TokenRecord>,
    pub signatures: QuorumSignatures,
}
impl FinalChunkClaimV1 {
    pub fn validate(&self) -> Result<(), NelError> {
        let n = usize::from(self.token_count);
        if !(1..32).contains(&n) || self.records.len() != n {
            return Err(NelError::InvalidCount);
        }
        let mut prev: Option<u32> = None;
        for r in &self.records {
            if let Some(p) = prev {
                if r.position == p {
                    return Err(NelError::DuplicatePosition);
                }
                if r.position != p.checked_add(1).ok_or(NelError::ArithmeticOverflow)? {
                    return Err(NelError::ReorderedRecord);
                }
            }
            prev = Some(r.position);
        }
        Ok(())
    }
    pub fn body_bytes(&self) -> Result<Vec<u8>, NelError> {
        self.validate()?;
        let capacity = 36usize
            .checked_mul(self.records.len())
            .and_then(|records| records.checked_add(FINAL_CHUNK_BASE_BYTES - 128))
            .ok_or(NelError::ArithmeticOverflow)?;
        let mut v = Vec::with_capacity(capacity);
        v.extend(self.s_start);
        v.extend(self.s_end);
        v.extend(self.chunk_trace_root);
        v.push(self.token_count);
        v.extend(self.toploc_fingerprint);
        for r in &self.records {
            v.extend(r.token_id.to_le_bytes());
            v.extend(r.logits_root)
        }
        Ok(v)
    }
    pub fn encode(&self) -> Result<Vec<u8>, NelError> {
        let mut v = self.body_bytes()?;
        v.extend(self.signatures.first);
        v.extend(self.signatures.second);
        Ok(v)
    }
    pub fn decode(b: &[u8], start_position: u32) -> Result<Self, NelError> {
        if b.len() < FINAL_CHUNK_BASE_BYTES {
            return Err(NelError::WrongLength);
        }
        let count = usize::from(b[96]);
        if !(1..32).contains(&count) {
            return Err(NelError::InvalidCount);
        }
        let expected = FINAL_CHUNK_BASE_BYTES
            .checked_add(
                36usize
                    .checked_mul(count)
                    .ok_or(NelError::ArithmeticOverflow)?,
            )
            .ok_or(NelError::ArithmeticOverflow)?;
        if b.len() != expected {
            return Err(NelError::WrongLength);
        }
        let mut o = 0;
        let s_start = take(b, &mut o)?;
        let s_end = take(b, &mut o)?;
        let chunk_trace_root = take(b, &mut o)?;
        let token_count = take::<1>(b, &mut o)?[0];
        let toploc_fingerprint = take(b, &mut o)?;
        let mut records = Vec::with_capacity(count);
        for i in 0..u32::from(token_count) {
            records.push(TokenRecord {
                position: start_position
                    .checked_add(i)
                    .ok_or(NelError::ArithmeticOverflow)?,
                token_id: u32_at(b, &mut o)?,
                logits_root: take(b, &mut o)?,
            });
        }
        let x = Self {
            s_start,
            s_end,
            chunk_trace_root,
            token_count,
            toploc_fingerprint,
            records,
            signatures: QuorumSignatures {
                first: take(b, &mut o)?,
                second: take(b, &mut o)?,
            },
        };
        finish(b, o)?;
        x.validate()?;
        Ok(x)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ChunkClaim {
    Full(ChunkClaimV1),
    Final(FinalChunkClaimV1),
}
impl ChunkClaim {
    pub fn validate_for_job(&self, chunk_index: u32, total_tokens: u32) -> Result<(), NelError> {
        let start = chunk_index
            .checked_mul(32)
            .ok_or(NelError::ArithmeticOverflow)?;
        let remaining = total_tokens
            .checked_sub(start)
            .ok_or(NelError::WrongChunkKind)?;
        match self {
            Self::Full(_) if remaining >= 32 => Ok(()),
            Self::Final(c)
                if remaining < 32 && remaining > 0 && u32::from(c.token_count) == remaining =>
            {
                c.validate()
            }
            _ => Err(NelError::WrongChunkKind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorTx {
    pub job_id: Hash32,
    pub chunk_index: u32,
    pub claim: ChunkClaim,
}
impl AnchorTx {
    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        let mut b = Vec::new();
        b.extend(self.job_id);
        b.extend(self.chunk_index.to_le_bytes());
        match &self.claim {
            ChunkClaim::Full(c) => {
                b.push(0);
                b.extend(c.encode())
            }
            ChunkClaim::Final(c) => {
                b.push(1);
                if let Ok(x) = c.encode() {
                    b.extend(x)
                }
            }
        }
        domain_hash(domains::ANCHOR_TX, &b)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FinalityClass {
    Soft,
    Anchored,
    Assured,
    Proven,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobReceipt {
    pub job_id: Hash32,
    pub model_id: Hash32,
    pub prompt_commitment: Hash32,
    pub token_history_root_final: Hash32,
    pub n_generated: u16,
    pub finality_class: FinalityClass,
    pub evidence_ptr: Hash32,
    pub chunk_claim_refs_root: Hash32,
    pub settlement_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorRegistration {
    pub executor_key: PublicKey,
    pub manifest_set: BTreeSet<Hash32>,
    pub failure_domains_root: Hash32,
    pub conformance_cert_ref: Hash32,
    pub bond: u64,
    pub exit_notice_height: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorStatus {
    Registered,
    Conformant,
    Eligible,
    Exiting,
    Released,
    Tombstoned,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorAccount {
    pub registration: ExecutorRegistration,
    pub status: ExecutorStatus,
    pub outstanding_claims: BTreeMap<Hash32, u64>,
}
impl ExecutorAccount {
    pub fn request_exit(&mut self, height: u64) -> Result<(), NelError> {
        if matches!(
            self.status,
            ExecutorStatus::Released | ExecutorStatus::Tombstoned
        ) {
            return Err(NelError::InvalidTransition);
        }
        self.status = ExecutorStatus::Exiting;
        self.registration.exit_notice_height = height;
        Ok(())
    }
    pub fn release(&mut self, height: u64) -> Result<u64, NelError> {
        if self.status != ExecutorStatus::Exiting {
            return Err(NelError::InvalidTransition);
        }
        if self
            .outstanding_claims
            .values()
            .any(|expiry| *expiry >= height)
        {
            return Err(NelError::OutstandingClaims);
        }
        self.status = ExecutorStatus::Released;
        Ok(self.registration.bond)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryStatus {
    Enabled,
    Disabled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProfile {
    pub id: u32,
    pub manifest: ModelManifest,
    pub parameter_count: u64,
    pub status: RegistryStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumericProfile {
    pub id: u32,
    pub profile_hash: Hash32,
    pub silu_table_hash: Hash32,
    pub version: u16,
    pub status: RegistryStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodingMode {
    GreedyLowestTokenId,
    Sampling,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodingProfile {
    pub id: u32,
    pub mode: DecodingMode,
    pub status: RegistryStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierId {
    EnvelopeV1 = 1,
    Risc0FreivaldsLeafV1 = 2,
    Risc0NonlinearLeafV1 = 3,
    SpecializedChunkV1 = 4,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierProfile {
    pub id: VerifierId,
    pub image_id: Hash32,
    pub verifier_key: PublicKey,
    pub max_proof_bytes: u32,
    pub status: RegistryStatus,
}
#[derive(Debug, Default, Clone)]
pub struct Registries {
    models: BTreeMap<u32, ModelProfile>,
    numeric: BTreeMap<u32, NumericProfile>,
    decoding: BTreeMap<u32, DecodingProfile>,
    verifiers: BTreeMap<u8, VerifierProfile>,
    executors: BTreeMap<PublicKey, ExecutorAccount>,
}
fn insert_once<K: Ord, V>(m: &mut BTreeMap<K, V>, k: K, v: V) -> Result<(), NelError> {
    if m.contains_key(&k) {
        return Err(NelError::ImmutableRegistry);
    }
    m.insert(k, v);
    Ok(())
}
impl Registries {
    pub fn first_activation(
        model: ModelProfile,
        numeric: NumericProfile,
        verifiers: [VerifierProfile; 3],
    ) -> Result<Self, NelError> {
        if model.id != 1
            || model.parameter_count != 494_000_000
            || model.status != RegistryStatus::Enabled
            || numeric.id != 1
            || numeric.version == 0
            || numeric.status != RegistryStatus::Enabled
            || model.manifest.circuit_id != [0; 32]
        {
            return Err(NelError::UnsupportedMode);
        }
        let mut r = Self::default();
        r.models.insert(1, model);
        r.numeric.insert(1, numeric);
        r.decoding.insert(
            1,
            DecodingProfile {
                id: 1,
                mode: DecodingMode::GreedyLowestTokenId,
                status: RegistryStatus::Enabled,
            },
        );
        for v in verifiers {
            if v.id == VerifierId::SpecializedChunkV1 || v.status != RegistryStatus::Enabled {
                return Err(NelError::UnsupportedMode);
            }
            r.verifiers.insert(v.id as u8, v);
        }
        Ok(r)
    }
    pub fn register_executor(&mut self, reg: ExecutorRegistration) -> Result<(), NelError> {
        if reg.manifest_set.is_empty() || reg.bond == 0 {
            return Err(NelError::InvalidBond);
        }
        insert_once(
            &mut self.executors,
            reg.executor_key,
            ExecutorAccount {
                registration: reg,
                status: ExecutorStatus::Registered,
                outstanding_claims: BTreeMap::new(),
            },
        )
    }
    pub fn verifier(&self, id: VerifierId) -> Result<&VerifierProfile, NelError> {
        let v = self
            .verifiers
            .get(&(id as u8))
            .ok_or(NelError::UnknownRegistryId)?;
        if v.status != RegistryStatus::Enabled {
            return Err(NelError::DisabledRegistryId);
        }
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeV1 {
    pub verifier_id: VerifierId,
    pub image_id: Hash32,
    pub public_input_hash: Hash32,
    pub proof: Vec<u8>,
}
impl EnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, NelError> {
        let n = u32::try_from(self.proof.len()).map_err(|_| NelError::ProofTooLarge)?;
        let capacity = 69usize
            .checked_add(self.proof.len())
            .ok_or(NelError::ProofTooLarge)?;
        let mut v = Vec::with_capacity(capacity);
        v.push(self.verifier_id as u8);
        v.extend(self.image_id);
        v.extend(self.public_input_hash);
        v.extend(n.to_le_bytes());
        v.extend(&self.proof);
        Ok(v)
    }
    pub fn decode(b: &[u8], max: u32) -> Result<Self, NelError> {
        if b.len() < 69 {
            return Err(NelError::MalformedEnvelope);
        }
        let mut o = 0;
        let verifier_id = match take::<1>(b, &mut o)?[0] {
            1 => VerifierId::EnvelopeV1,
            2 => VerifierId::Risc0FreivaldsLeafV1,
            3 => VerifierId::Risc0NonlinearLeafV1,
            4 => VerifierId::SpecializedChunkV1,
            _ => return Err(NelError::UnknownRegistryId),
        };
        let image_id = take(b, &mut o)?;
        let public_input_hash = take(b, &mut o)?;
        let n = u32_at(b, &mut o)?;
        if n > max {
            return Err(NelError::ProofTooLarge);
        }
        let n = usize::try_from(n).map_err(|_| NelError::ProofTooLarge)?;
        if b.len() != 69usize.checked_add(n).ok_or(NelError::ProofTooLarge)? {
            return Err(NelError::MalformedEnvelope);
        }
        let proof = b[o..].to_vec();
        Ok(Self {
            verifier_id,
            image_id,
            public_input_hash,
            proof,
        })
    }
    pub fn verify(&self, registry: &Registries, expected_input: &Hash32) -> Result<(), NelError> {
        let p = registry.verifier(self.verifier_id)?;
        if self.verifier_id == VerifierId::SpecializedChunkV1 {
            return Err(NelError::DisabledRegistryId);
        }
        if self.image_id != p.image_id || self.public_input_hash != *expected_input {
            return Err(NelError::InvalidProof);
        }
        if self.proof.len() != 64
            || self.proof.len()
                > usize::try_from(p.max_proof_bytes).map_err(|_| NelError::ProofTooLarge)?
        {
            return Err(NelError::MalformedEnvelope);
        }
        let mut body = Vec::with_capacity(65);
        body.push(self.verifier_id as u8);
        body.extend(self.image_id);
        body.extend(self.public_input_hash);
        let sig: Signature = self
            .proof
            .as_slice()
            .try_into()
            .map_err(|_| NelError::MalformedEnvelope)?;
        verify_sig(&p.verifier_key, domains::ENVELOPE, &body, &sig)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreivaldsProfile {
    StandardReps2,
    ProductionReps4,
}
impl FreivaldsProfile {
    #[must_use]
    pub const fn reps(self) -> usize {
        match self {
            Self::StandardReps2 => 2,
            Self::ProductionReps4 => 4,
        }
    }
}
#[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects)]
pub fn freivalds_verify_u64(
    a: &[u64],
    b: &[u64],
    c: &[u64],
    m: usize,
    k: usize,
    n: usize,
    vectors: &[Vec<u32>],
    profile: FreivaldsProfile,
) -> Result<bool, NelError> {
    if a.len() != m.checked_mul(k).ok_or(NelError::ArithmeticOverflow)?
        || b.len() != k.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?
        || c.len() != m.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?
        || vectors.len() != profile.reps()
        || vectors.iter().any(|r| r.len() != n)
    {
        return Err(NelError::InvalidCount);
    }
    for r in vectors {
        let mut br = vec![0u64; k];
        for row in 0..k {
            let mut sum = 0u64;
            for col in 0..n {
                sum = sum.wrapping_add(b[row * n + col].wrapping_mul(u64::from(r[col])))
            }
            br[row] = sum;
        }
        for row in 0..m {
            let mut left = 0u64;
            let mut right = 0u64;
            for x in 0..k {
                left = left.wrapping_add(a[row * k + x].wrapping_mul(br[x]))
            }
            for col in 0..n {
                right = right.wrapping_add(c[row * n + col].wrapping_mul(u64::from(r[col])))
            }
            if left != right {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeOpen {
    pub dispute_id: Hash32,
    pub chunk_claim_ref: Hash32,
    pub challenger: PublicKey,
    pub challenger_bond: u64,
    pub alleged_s_end: Hash32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeStage {
    Chunk,
    Token,
    Layer,
    Op,
    Leaf,
    Resolved,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BisectMove {
    pub dispute_id: Hash32,
    pub round: u16,
    pub position: u32,
    pub left: Hash32,
    pub right: Hash32,
    pub mover: PublicKey,
    pub signature: Signature,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafReceipt {
    pub dispute_id: Hash32,
    pub token_position: u32,
    pub layer: u16,
    pub op: u16,
    pub envelope: EnvelopeV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    ExecutorFault,
    ChallengerFault,
    ExecutorTimeout,
    ChallengerTimeout,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispute {
    pub open: DisputeOpen,
    pub stage: DisputeStage,
    pub round: u16,
    pub position: u32,
    pub executor: PublicKey,
    pub next_mover: PublicKey,
    pub deadline_height: u64,
    pub availability_paused_since: Option<u64>,
    pub total_paused: u64,
}
impl Dispute {
    pub fn new(open: DisputeOpen, executor: PublicKey, height: u64) -> Result<Self, NelError> {
        if open.challenger == executor || open.challenger_bond == 0 {
            return Err(NelError::InvalidBond);
        }
        Ok(Self {
            next_mover: executor,
            open,
            stage: DisputeStage::Chunk,
            round: 0,
            position: 0,
            executor,
            deadline_height: height
                .checked_add(MOVE_DEADLINE_BLOCKS)
                .ok_or(NelError::ArithmeticOverflow)?,
            availability_paused_since: None,
            total_paused: 0,
        })
    }
    pub fn pause_unavailable(&mut self, height: u64) {
        if self.availability_paused_since.is_none() {
            self.availability_paused_since = Some(height)
        }
    }
    pub fn resume_available(&mut self, height: u64) -> Result<(), NelError> {
        let since = self
            .availability_paused_since
            .take()
            .ok_or(NelError::InvalidTransition)?;
        let paused = height
            .checked_sub(since)
            .ok_or(NelError::InvalidTransition)?;
        self.total_paused = self
            .total_paused
            .checked_add(paused)
            .ok_or(NelError::ArithmeticOverflow)?;
        self.deadline_height = self
            .deadline_height
            .checked_add(paused)
            .ok_or(NelError::ArithmeticOverflow)?;
        Ok(())
    }
    pub fn apply_move(&mut self, m: &BisectMove, height: u64) -> Result<(), NelError> {
        if self.availability_paused_since.is_some() {
            return Err(NelError::ClockPaused);
        }
        if height > self.deadline_height {
            return Err(NelError::Deadline);
        }
        if m.dispute_id != self.open.dispute_id || m.mover != self.next_mover {
            return Err(NelError::WrongMover);
        }
        if m.round != self.round || m.position != self.position {
            return Err(NelError::WrongRound);
        }
        let mut body = Vec::new();
        body.extend(m.dispute_id);
        body.extend(m.round.to_le_bytes());
        body.extend(m.position.to_le_bytes());
        body.extend(m.left);
        body.extend(m.right);
        verify_sig(&m.mover, domains::BISECT, &body, &m.signature)?;
        self.round = self
            .round
            .checked_add(1)
            .ok_or(NelError::ArithmeticOverflow)?;
        self.position = self
            .position
            .checked_mul(2)
            .ok_or(NelError::ArithmeticOverflow)?;
        self.stage = match self.stage {
            DisputeStage::Chunk => DisputeStage::Token,
            DisputeStage::Token => DisputeStage::Layer,
            DisputeStage::Layer => DisputeStage::Op,
            DisputeStage::Op => DisputeStage::Leaf,
            x => x,
        };
        self.next_mover = if self.next_mover == self.executor {
            self.open.challenger
        } else {
            self.executor
        };
        self.deadline_height = height
            .checked_add(MOVE_DEADLINE_BLOCKS)
            .ok_or(NelError::ArithmeticOverflow)?;
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashDistribution {
    pub challenger: u64,
    pub watch_pool: u64,
    pub burn: u64,
}
#[must_use]
pub fn distribute_executor_slash(amount: u64) -> SlashDistribution {
    let challenger = amount / 2;
    let watch_pool = amount / 5;
    SlashDistribution {
        challenger,
        watch_pool,
        burn: amount.saturating_sub(challenger).saturating_sub(watch_pool),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Open,
    Committee,
    Executing,
    Soft,
    Anchored,
    Assured,
    Disputed,
    Slashed,
    Refunded,
    Tombstoned,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRuntime {
    pub state: JobState,
    pub total_tokens: u32,
    pub anchored_chunks: BTreeSet<u32>,
    pub available_chunks: BTreeSet<u32>,
    pub anchor_deadlines: BTreeMap<u32, u64>,
    pub finality: Option<FinalityClass>,
    pub dependent_tail_from: Option<u32>,
    pub committee: [PublicKey; 3],
    pub committee_epoch: u64,
    pub value_ceiling: u64,
    pub dispute_cost_reserve: u64,
    pub bond_min: u64,
}
impl JobRuntime {
    pub fn validate_bond(&self) -> Result<(), NelError> {
        let required = self
            .value_ceiling
            .checked_mul(2)
            .and_then(|x| x.checked_add(self.dispute_cost_reserve))
            .ok_or(NelError::ArithmeticOverflow)?;
        if self.bond_min < required {
            return Err(NelError::InvalidBond);
        }
        Ok(())
    }
    pub fn soft(&mut self) -> Result<(), NelError> {
        if !matches!(self.state, JobState::Executing | JobState::Soft) {
            return Err(NelError::InvalidTransition);
        }
        self.state = JobState::Soft;
        self.finality = Some(FinalityClass::Soft);
        Ok(())
    }
    pub fn anchor(&mut self, index: u32, height: u64) -> Result<(), NelError> {
        if !matches!(self.state, JobState::Soft | JobState::Anchored) {
            return Err(NelError::InvalidTransition);
        }
        if self
            .anchor_deadlines
            .get(&index)
            .is_some_and(|d| height > *d)
        {
            return Err(NelError::AnchorDeadline);
        }
        self.anchored_chunks.insert(index);
        self.state = JobState::Anchored;
        self.finality = Some(FinalityClass::Anchored);
        Ok(())
    }
    pub fn mark_available(&mut self, index: u32) -> Result<(), NelError> {
        if !self.anchored_chunks.contains(&index) {
            return Err(NelError::InvalidTransition);
        }
        self.available_chunks.insert(index);
        Ok(())
    }
    pub fn assure(&mut self) -> Result<(), NelError> {
        if self.state != JobState::Anchored || self.available_chunks != self.anchored_chunks {
            return Err(NelError::AvailabilityRequired);
        }
        self.state = JobState::Assured;
        self.finality = Some(FinalityClass::Assured);
        Ok(())
    }
    pub fn invalidate_tail(
        &mut self,
        token: u32,
        fresh_committee: [PublicKey; 3],
        epoch: u64,
    ) -> Result<(), NelError> {
        if fresh_committee == self.committee || epoch <= self.committee_epoch {
            return Err(NelError::InvalidTransition);
        }
        self.dependent_tail_from = Some(token);
        self.committee = fresh_committee;
        self.committee_epoch = epoch;
        self.state = JobState::Slashed;
        self.finality = None;
        Ok(())
    }
    pub fn tombstone(&mut self) -> Result<(), NelError> {
        if !matches!(
            self.state,
            JobState::Assured | JobState::Refunded | JobState::Slashed
        ) {
            return Err(NelError::InvalidTransition);
        }
        self.state = JobState::Tombstoned;
        Ok(())
    }
}

#[must_use]
pub fn greedy_token(logits: &[i32]) -> Option<u32> {
    logits
        .iter()
        .enumerate()
        .max_by(|(ia, a), (ib, b)| a.cmp(b).then_with(|| ib.cmp(ia)))
        .and_then(|(i, _)| u32::try_from(i).ok())
}
#[must_use]
pub fn activation_blockers() -> [&'static str; 6] {
    ["E-NEL-01: >=10^9 cross-vendor operator instances, two CPU implementations, AMD and NVIDIA integer kernels, zero mismatches","E-NEL-02: real registered 0.5B accuracy gate","E-NEL-03: committed-token latency p95 <2s and p99 <5s","E-NEL-04: T=32 dispute ~19 rounds/~40 transactions/~8.1KB and <6h","E-NEL-05: 99.9% witness retrieval over 30 days","Operator gate: >=3 independent operators and >=2 funded challengers"]
}

#[cfg(test)]
mod tests;
