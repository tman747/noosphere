//! BESI split prototype conformance. This crate is research-only and has no activation API.
#![forbid(unsafe_code)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::possible_missing_else
)]
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeSet;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod delivery;
pub mod depth;
pub mod dual_root;
pub mod fused_audit;
pub mod hfhe;
pub mod mpc3;
pub mod refresh;
pub mod transformer;
pub mod transition_market;

pub const PRIVACY_PROFILE: &str = "P3_DEEP_SEALED";
pub const EXECUTION_MODE: &str = "BESI_SPLIT_PROTOTYPE";
pub const ASSURANCE: &str = "ASSURED_SPLIT";
pub const PADDING_BUCKET: usize = 128;
pub const DISPUTE_SUITE: &str = "AUTHENTICATED-PRIVATE-WITNESS-ADJUDICATION-ED25519-v1";
pub const MALICIOUS_3PC_STATUS: ExperimentStatus=ExperimentStatus::Disabled("requires audited MP-SPDZ backend, preprocessing ceremony, MAC/sacrifice checks, private full-transformer relation, independent verifier, and malicious-party harness");
pub const HFHE_STATUS: ExperimentStatus=ExperimentStatus::Disabled("requires standard-assumption reduction, concrete parameters, compact repeatable refresh, public proof, independent implementation, and mutation/performance gates");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentStatus {
    Disabled(&'static str),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BesiError {
    Shape,
    Overflow,
    Context,
    Replay,
    Decrypt,
    FreivaldsMismatch,
    RawSharePublicDa,
    Signature,
    UnknownSuite,
    Epoch,
    AssuranceSubstitution,
    NonCanonical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<u64>,
}
impl Matrix {
    pub fn new(rows: usize, cols: usize, data: Vec<u64>) -> Result<Self, BesiError> {
        if rows.checked_mul(cols) != Some(data.len()) {
            Err(BesiError::Shape)
        } else {
            Ok(Self { rows, cols, data })
        }
    }
    fn at(&self, r: usize, c: usize) -> u64 {
        self.data[r * self.cols + c]
    }
}

#[must_use]
pub fn encode_matrix(matrix: &Matrix) -> Vec<u8> {
    let mut encoded = b"NOOS/BESI/MATRIX/Z2-64/V1".to_vec();
    encoded.extend_from_slice(&(matrix.rows as u64).to_le_bytes());
    encoded.extend_from_slice(&(matrix.cols as u64).to_le_bytes());
    encoded.extend_from_slice(&(matrix.data.len() as u64).to_le_bytes());
    for value in &matrix.data {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    encoded
}

pub fn decode_matrix(encoded: &[u8]) -> Result<Matrix, BesiError> {
    const DOMAIN: &[u8] = b"NOOS/BESI/MATRIX/Z2-64/V1";
    if !encoded.starts_with(DOMAIN) || encoded.len() < DOMAIN.len() + 24 {
        return Err(BesiError::NonCanonical);
    }
    let mut offset = DOMAIN.len();
    let mut take_u64 = || {
        let end = offset.checked_add(8).ok_or(BesiError::Overflow)?;
        let bytes: [u8; 8] = encoded
            .get(offset..end)
            .ok_or(BesiError::NonCanonical)?
            .try_into()
            .map_err(|_| BesiError::NonCanonical)?;
        offset = end;
        Ok::<u64, BesiError>(u64::from_le_bytes(bytes))
    };
    let rows = usize::try_from(take_u64()?).map_err(|_| BesiError::Overflow)?;
    let cols = usize::try_from(take_u64()?).map_err(|_| BesiError::Overflow)?;
    let count = usize::try_from(take_u64()?).map_err(|_| BesiError::Overflow)?;
    let expected = offset
        .checked_add(count.checked_mul(8).ok_or(BesiError::Overflow)?)
        .ok_or(BesiError::Overflow)?;
    if expected != encoded.len() || rows.checked_mul(cols) != Some(count) {
        return Err(BesiError::NonCanonical);
    }
    let mut data = Vec::with_capacity(count);
    while offset < encoded.len() {
        let bytes: [u8; 8] = encoded[offset..offset + 8]
            .try_into()
            .map_err(|_| BesiError::NonCanonical)?;
        data.push(u64::from_le_bytes(bytes));
        offset += 8;
    }
    Matrix::new(rows, cols, data)
}

/// Fresh additive sharing over Z/(2^64). `random_share` must come from an OS CSPRNG in production callers.
pub fn split(plain: &Matrix, random_share: Vec<u64>) -> Result<(Matrix, Matrix), BesiError> {
    if random_share.len() != plain.data.len() {
        return Err(BesiError::Shape);
    }
    let complement = plain
        .data
        .iter()
        .zip(&random_share)
        .map(|(x, r)| x.wrapping_sub(*r))
        .collect();
    Ok((
        Matrix::new(plain.rows, plain.cols, random_share)?,
        Matrix::new(plain.rows, plain.cols, complement)?,
    ))
}
pub fn reconstruct(a: &Matrix, b: &Matrix) -> Result<Matrix, BesiError> {
    if a.rows != b.rows || a.cols != b.cols {
        return Err(BesiError::Shape);
    }
    Matrix::new(
        a.rows,
        a.cols,
        a.data
            .iter()
            .zip(&b.data)
            .map(|(x, y)| x.wrapping_add(*y))
            .collect(),
    )
}
pub fn raw_public_weight_gemm(x: &Matrix, w: &Matrix) -> Result<Matrix, BesiError> {
    if x.cols != w.rows {
        return Err(BesiError::Shape);
    }
    let mut out = vec![0u64; x.rows * w.cols];
    for r in 0..x.rows {
        for c in 0..w.cols {
            let mut z = 0u64;
            for k in 0..x.cols {
                z = z.wrapping_add(x.at(r, k).wrapping_mul(w.at(k, c)));
            }
            out[r * w.cols + c] = z;
        }
    }
    Matrix::new(x.rows, w.cols, out)
}

pub fn pad_rows(x: &Matrix) -> Result<(Matrix, usize), BesiError> {
    let padded = x
        .rows
        .checked_add(PADDING_BUCKET - 1)
        .ok_or(BesiError::Overflow)?
        / PADDING_BUCKET
        * PADDING_BUCKET;
    let len = padded.checked_mul(x.cols).ok_or(BesiError::Overflow)?;
    let mut data = vec![0; len];
    data[..x.data.len()].copy_from_slice(&x.data);
    Ok((Matrix::new(padded, x.cols, data)?, x.rows))
}
pub fn slice_after_verification(
    y: &Matrix,
    true_rows: usize,
    verified: bool,
) -> Result<Matrix, BesiError> {
    if !verified {
        return Err(BesiError::FreivaldsMismatch);
    }
    if true_rows > y.rows {
        return Err(BesiError::Shape);
    }
    Matrix::new(true_rows, y.cols, y.data[..true_rows * y.cols].to_vec())
}

/// Exact-Z Freivalds on the reconstructed padded raw accumulator. Signed values are lifted from
/// their two's-complement representation and all arithmetic is checked i128 before comparison.
pub fn freivalds_exact_z(
    x: &Matrix,
    w: &Matrix,
    y: &Matrix,
    challenges: &[Vec<i64>],
) -> Result<(), BesiError> {
    if x.cols != w.rows || x.rows != y.rows || w.cols != y.cols || challenges.is_empty() {
        return Err(BesiError::Shape);
    }
    for challenge in challenges {
        if challenge.len() != w.cols {
            return Err(BesiError::Shape);
        }
        for row in 0..x.rows {
            let mut lhs = 0i128;
            for c in 0..y.cols {
                lhs = lhs
                    .checked_add(
                        (y.at(row, c) as i64 as i128)
                            .checked_mul(challenge[c] as i128)
                            .ok_or(BesiError::Overflow)?,
                    )
                    .ok_or(BesiError::Overflow)?;
            }
            let mut rhs = 0i128;
            for k in 0..x.cols {
                let mut wr = 0i128;
                for c in 0..w.cols {
                    wr = wr
                        .checked_add(
                            (w.at(k, c) as i64 as i128)
                                .checked_mul(challenge[c] as i128)
                                .ok_or(BesiError::Overflow)?,
                        )
                        .ok_or(BesiError::Overflow)?;
                }
                rhs = rhs
                    .checked_add(
                        (x.at(row, k) as i64 as i128)
                            .checked_mul(wr)
                            .ok_or(BesiError::Overflow)?,
                    )
                    .ok_or(BesiError::Overflow)?;
            }
            if lhs != rhs {
                return Err(BesiError::FreivaldsMismatch);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelContext {
    pub party: u8,
    pub request_id: [u8; 32],
    pub model_hash: [u8; 32],
    pub numeric_profile: [u8; 32],
    pub tensor_id: [u8; 32],
    pub rows: u32,
    pub cols: u32,
    pub chunk: u32,
    pub block_order: u32,
    pub key_epoch: u64,
    pub direction: Direction,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Request,
    Response,
}
impl ChannelContext {
    pub fn aad(&self) -> Vec<u8> {
        let mut o = b"NOOS/BESI/CHANNEL-CONTEXT/V1".to_vec();
        o.push(self.party);
        o.extend_from_slice(&self.request_id);
        o.extend_from_slice(&self.model_hash);
        o.extend_from_slice(&self.numeric_profile);
        o.extend_from_slice(&self.tensor_id);
        for x in [self.rows, self.cols, self.chunk, self.block_order] {
            o.extend_from_slice(&x.to_le_bytes())
        }
        o.extend_from_slice(&self.key_epoch.to_le_bytes());
        o.push(match self.direction {
            Direction::Request => 0,
            Direction::Response => 1,
        });
        o
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub sender_public: [u8; 32],
    pub nonce: [u8; 12],
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
}

fn channel_key(
    secret: &StaticSecret,
    peer: &PublicKey,
    ctx: &ChannelContext,
) -> Result<[u8; 32], BesiError> {
    let shared = secret.diffie_hellman(peer);
    let hk = Hkdf::<Sha256>::new(Some(b"NOOS/BESI/X25519-HKDF-SHA256/V1"), shared.as_bytes());
    let mut key = [0; 32];
    hk.expand(&ctx.aad(), &mut key)
        .map_err(|_| BesiError::Context)?;
    Ok(key)
}
pub fn encrypt(
    secret: &StaticSecret,
    peer: &PublicKey,
    ctx: &ChannelContext,
    nonce: [u8; 12],
    sequence: u64,
    plain: &[u8],
) -> Result<Envelope, BesiError> {
    let mut aad = ctx.aad();
    aad.extend_from_slice(&sequence.to_le_bytes());
    let key = channel_key(secret, peer, ctx)?;
    let ciphertext = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| BesiError::Decrypt)?;
    Ok(Envelope {
        sender_public: PublicKey::from(secret).to_bytes(),
        nonce,
        sequence,
        ciphertext,
    })
}
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    seen: BTreeSet<([u8; 32], u64, u64)>,
}
impl ReplayGuard {
    pub fn decrypt(
        &mut self,
        secret: &StaticSecret,
        ctx: &ChannelContext,
        envelope: &Envelope,
    ) -> Result<Vec<u8>, BesiError> {
        let replay = (ctx.request_id, ctx.key_epoch, envelope.sequence);
        if self.seen.contains(&replay) {
            return Err(BesiError::Replay);
        }
        let peer = PublicKey::from(envelope.sender_public);
        let key = channel_key(secret, &peer, ctx)?;
        let mut aad = ctx.aad();
        aad.extend_from_slice(&envelope.sequence.to_le_bytes());
        let plain = ChaCha20Poly1305::new((&key).into())
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BesiError::Decrypt)?;
        self.seen.insert(replay);
        Ok(plain)
    }
    pub fn rotate_epoch(&mut self, new_epoch: u64) {
        self.seen.retain(|(_, epoch, _)| *epoch >= new_epoch);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicDaArtifact {
    CiphertextCommitment([u8; 32]),
    TranscriptRoot([u8; 32]),
    OutputCommitment([u8; 32]),
    RawActivationShare(Vec<u8>),
    RawAccumulatorShare(Vec<u8>),
}
pub fn admit_public_da(a: &PublicDaArtifact) -> Result<(), BesiError> {
    match a {
        PublicDaArtifact::RawActivationShare(_) | PublicDaArtifact::RawAccumulatorShare(_) => {
            Err(BesiError::RawSharePublicDa)
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Accept,
    Executor0Fault,
    Executor1Fault,
    ClientFault,
    AbortRefund,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdjudicationReceipt {
    pub job_id: [u8; 32],
    pub ordered_response_ciphertext_commitments: [[u8; 32]; 2],
    pub output_commitment: [u8; 32],
    pub private_witness_proof_root: [u8; 32],
    pub suite: String,
    pub verdict: Verdict,
    pub epoch: u64,
    pub nonce: u64,
    pub signature: [u8; 64],
}
impl AdjudicationReceipt {
    pub fn message(&self) -> Vec<u8> {
        let mut o = b"NOOS/BESI/PRIVATE-ADJUDICATION/V1".to_vec();
        o.extend_from_slice(&self.job_id);
        for h in self.ordered_response_ciphertext_commitments {
            o.extend_from_slice(&h)
        }
        o.extend_from_slice(&self.output_commitment);
        o.extend_from_slice(&self.private_witness_proof_root);
        o.extend_from_slice(&(self.suite.len() as u32).to_le_bytes());
        o.extend_from_slice(self.suite.as_bytes());
        o.push(match self.verdict {
            Verdict::Accept => 0,
            Verdict::Executor0Fault => 1,
            Verdict::Executor1Fault => 2,
            Verdict::ClientFault => 3,
            Verdict::AbortRefund => 4,
        });
        o.extend_from_slice(&self.epoch.to_le_bytes());
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o
    }
    pub fn verify(
        &self,
        key: &VerifyingKey,
        expected_epoch: u64,
        used: &mut BTreeSet<(u64, u64)>,
    ) -> Result<(), BesiError> {
        if self.suite != DISPUTE_SUITE {
            return Err(BesiError::UnknownSuite);
        }
        if self.epoch != expected_epoch {
            return Err(BesiError::Epoch);
        }
        if used.contains(&(self.epoch, self.nonce)) {
            return Err(BesiError::Replay);
        }
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&self.message(), &sig)
            .map_err(|_| BesiError::Signature)?;
        used.insert((self.epoch, self.nonce));
        Ok(())
    }
}

#[must_use]
pub fn exact_assurance(profile: &str, mode: &str, assurance: &str) -> bool {
    profile == PRIVACY_PROFILE && mode == EXECUTION_MODE && assurance == ASSURANCE
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanitizedBesiResult {
    pub job_id: [u8; 32],
    pub output_commitment: [u8; 32],
    pub integrity: bool,
    pub public_bucket: usize,
    pub remote_gemms: u32,
    pub assurance: &'static str,
}

impl SanitizedBesiResult {
    #[must_use]
    pub fn field_names() -> [&'static str; 6] {
        [
            "job_id",
            "output_commitment",
            "integrity",
            "public_bucket",
            "remote_gemms",
            "assurance",
        ]
    }
}
#[cfg(test)]
mod tests;
