//! Full transformer block over the BESI conformance encoding, end to end and deterministic.
//!
//! The block runs the frozen integer profile (RMSNorm, QKV projections, two-head integer
//! attention, output projection, gated integer FFN, residuals) with every public-weight GEMM
//! routed through a pluggable engine. The plaintext engine multiplies directly; the BESI split
//! engine pads each activation to the 128-row bucket, splits it into two fresh uniform ring
//! shares, runs both executor raw GEMMs, reconstructs, and requires two exact-Z Freivalds
//! challenges to accept before slicing and requantization. The conformance contract is bitwise
//! equality of the two paths; a tampered executor share must reject with `FreivaldsMismatch`
//! before any slicing happens.
//!
//! Dimensions are deliberately small (seq 4, d_model 8, 2 heads, d_ff 16) so the whole block,
//! including 128-row physical padding on all six remote GEMMs, runs in test time. The nonlinear
//! profile is this crate's frozen integer test profile, not any production model's.

use crate::{
    freivalds_exact_z, pad_rows, raw_public_weight_gemm, reconstruct, slice_after_verification,
    split, BesiError, Matrix,
};

pub const SEQ: usize = 4;
pub const D_MODEL: usize = 8;
pub const HEADS: usize = 2;
pub const D_HEAD: usize = D_MODEL / HEADS;
pub const D_FF: usize = 16;
pub const REQUANT_SHIFT: u32 = 4;
pub const FREIVALDS_CHALLENGES: usize = 2;

fn signed(v: u64) -> i64 {
    v as i64
}

fn unsigned(v: i64) -> u64 {
    v as u64
}

/// Public-weight GEMM boundary: exactly the work BESI outsources.
pub trait GemmEngine {
    fn gemm(&mut self, x: &Matrix, w: &Matrix) -> Result<Matrix, BesiError>;
}

/// Client-local reference path.
#[derive(Default)]
pub struct PlainEngine;

impl GemmEngine for PlainEngine {
    fn gemm(&mut self, x: &Matrix, w: &Matrix) -> Result<Matrix, BesiError> {
        raw_public_weight_gemm(x, w)
    }
}

/// Two-executor split path with mandatory exact-Z verification before slicing.
pub struct BesiSplitEngine {
    reader: blake3::OutputReader,
    pub remote_gemms: u32,
    /// Test hook: add 1 to executor 0's first accumulator word on the numbered remote GEMM.
    pub tamper_gemm: Option<u32>,
}

impl BesiSplitEngine {
    #[must_use]
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(seed);
        hasher.update(b"NOOS/BESI/TRANSFORMER-SPLIT/V1");
        Self {
            reader: hasher.finalize_xof(),
            remote_gemms: 0,
            tamper_gemm: None,
        }
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.reader.fill(&mut buf);
        u64::from_le_bytes(buf)
    }
    /// Bounded odd challenge entries keep the exact-Z i128 envelope comfortable.
    fn challenge(&mut self, len: usize) -> Vec<i64> {
        (0..len)
            .map(|_| {
                let v = self.next_u64();
                let magnitude = (v % 1021) as i64 + 1;
                if v & (1 << 63) == 0 {
                    magnitude
                } else {
                    -magnitude
                }
            })
            .collect()
    }
}

impl GemmEngine for BesiSplitEngine {
    fn gemm(&mut self, x: &Matrix, w: &Matrix) -> Result<Matrix, BesiError> {
        let index = self.remote_gemms;
        self.remote_gemms = self.remote_gemms.saturating_add(1);
        let (padded, true_rows) = pad_rows(x)?;
        let mask: Vec<u64> = (0..padded.data.len()).map(|_| self.next_u64()).collect();
        let (x0, x1) = split(&padded, mask)?;
        // Remote executors: raw public-weight accumulators over one share each.
        let mut y0 = raw_public_weight_gemm(&x0, w)?;
        let y1 = raw_public_weight_gemm(&x1, w)?;
        if self.tamper_gemm == Some(index) {
            y0.data[0] = y0.data[0].wrapping_add(1);
        }
        let y = reconstruct(&y0, &y1)?;
        // Mandatory exact-Z Freivalds before anything is sliced or requantized.
        let challenges: Vec<Vec<i64>> = (0..FREIVALDS_CHALLENGES)
            .map(|_| self.challenge(w.cols))
            .collect();
        freivalds_exact_z(&padded, w, &y, &challenges)?;
        slice_after_verification(&y, true_rows, true)
    }
}

/// Truncating arithmetic right shift on the signed view (frozen requantization).
fn requantize(y: &Matrix) -> Matrix {
    Matrix {
        rows: y.rows,
        cols: y.cols,
        data: y
            .data
            .iter()
            .map(|v| unsigned(signed(*v) >> REQUANT_SHIFT))
            .collect(),
    }
}

fn isqrt(v: i64) -> i64 {
    let mut low = 0i64;
    let mut high = v.max(1);
    while low < high {
        let mid = (low + high + 1) / 2;
        if mid.saturating_mul(mid) <= v {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

/// Integer RMSNorm: y = x * 16 / isqrt(mean(x^2) + 1), rowwise.
fn rms_norm(x: &Matrix) -> Matrix {
    let mut data = Vec::with_capacity(x.data.len());
    for row in 0..x.rows {
        let mut sum_squares = 0i64;
        for col in 0..x.cols {
            let v = signed(x.at(row, col));
            sum_squares = sum_squares.saturating_add(v.saturating_mul(v));
        }
        let denom = isqrt(sum_squares / x.cols as i64 + 1).max(1);
        for col in 0..x.cols {
            data.push(unsigned(signed(x.at(row, col)).saturating_mul(16) / denom));
        }
    }
    Matrix {
        rows: x.rows,
        cols: x.cols,
        data,
    }
}

/// Frozen integer attention weights: shifted-ReLU scores, fixed-point normalized.
fn attention(q: &Matrix, k: &Matrix, v: &Matrix) -> Matrix {
    let mut out = vec![0u64; SEQ * D_MODEL];
    for head in 0..HEADS {
        let base = head * D_HEAD;
        for i in 0..SEQ {
            // Scores for query row i against every key row.
            let mut weights = [0i64; SEQ];
            let mut max_score = i64::MIN;
            let mut scores = [0i64; SEQ];
            for j in 0..SEQ {
                let mut s = 0i64;
                for c in 0..D_HEAD {
                    s = s.saturating_add(
                        signed(q.at(i, base + c)).saturating_mul(signed(k.at(j, base + c))),
                    );
                }
                scores[j] = s >> 2;
                max_score = max_score.max(scores[j]);
            }
            let mut total = 0i64;
            for j in 0..SEQ {
                weights[j] = (scores[j] - max_score + 16).max(1);
                total = total.saturating_add(weights[j]);
            }
            for c in 0..D_HEAD {
                let mut acc = 0i64;
                for j in 0..SEQ {
                    acc = acc.saturating_add(weights[j].saturating_mul(signed(v.at(j, base + c))));
                }
                out[i * D_MODEL + base + c] = unsigned(acc / total);
            }
        }
    }
    Matrix {
        rows: SEQ,
        cols: D_MODEL,
        data: out,
    }
}

/// Frozen integer SiLU-like gate: t * clamp(t + 8, 0, 16) / 16.
fn gate(x: &Matrix) -> Matrix {
    Matrix {
        rows: x.rows,
        cols: x.cols,
        data: x
            .data
            .iter()
            .map(|v| {
                let t = signed(*v);
                unsigned(t.saturating_mul((t.saturating_add(8)).clamp(0, 16)) / 16)
            })
            .collect(),
    }
}

fn residual_add(x: &Matrix, y: &Matrix) -> Result<Matrix, BesiError> {
    if x.rows != y.rows || x.cols != y.cols {
        return Err(BesiError::Shape);
    }
    Ok(Matrix {
        rows: x.rows,
        cols: x.cols,
        data: x
            .data
            .iter()
            .zip(&y.data)
            .map(|(a, b)| unsigned(signed(*a).wrapping_add(signed(*b))))
            .collect(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockWeights {
    pub wq: Matrix,
    pub wk: Matrix,
    pub wv: Matrix,
    pub wo: Matrix,
    pub w1: Matrix,
    pub w2: Matrix,
}

fn small_matrix(reader: &mut blake3::OutputReader, rows: usize, cols: usize, span: i64) -> Matrix {
    let mut buf = [0u8; 8];
    let width = 2 * span + 1;
    let data = (0..rows * cols)
        .map(|_| {
            reader.fill(&mut buf);
            let v = u64::from_le_bytes(buf);
            unsigned((v % width as u64) as i64 - span)
        })
        .collect();
    Matrix { rows, cols, data }
}

/// Deterministic frozen weights, entries in [-3, 3].
#[must_use]
pub fn deterministic_weights(seed: &[u8; 32]) -> BlockWeights {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(b"NOOS/BESI/TRANSFORMER-WEIGHTS/V1");
    let mut reader = hasher.finalize_xof();
    BlockWeights {
        wq: small_matrix(&mut reader, D_MODEL, D_MODEL, 3),
        wk: small_matrix(&mut reader, D_MODEL, D_MODEL, 3),
        wv: small_matrix(&mut reader, D_MODEL, D_MODEL, 3),
        wo: small_matrix(&mut reader, D_MODEL, D_MODEL, 3),
        w1: small_matrix(&mut reader, D_MODEL, D_FF, 3),
        w2: small_matrix(&mut reader, D_FF, D_MODEL, 3),
    }
}

/// Deterministic activation input, entries in [-8, 8].
#[must_use]
pub fn deterministic_input(seed: &[u8; 32]) -> Matrix {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(b"NOOS/BESI/TRANSFORMER-INPUT/V1");
    let mut reader = hasher.finalize_xof();
    small_matrix(&mut reader, SEQ, D_MODEL, 8)
}

/// One full transformer block. Exactly six public-weight GEMMs cross the engine boundary; all
/// nonlinear, KV, and residual work stays with the client, as in the BESI placement.
pub fn transformer_block(
    x: &Matrix,
    weights: &BlockWeights,
    engine: &mut dyn GemmEngine,
) -> Result<Matrix, BesiError> {
    let normed = rms_norm(x);
    let q = requantize(&engine.gemm(&normed, &weights.wq)?);
    let k = requantize(&engine.gemm(&normed, &weights.wk)?);
    let v = requantize(&engine.gemm(&normed, &weights.wv)?);
    let attended = attention(&q, &k, &v);
    let projected = requantize(&engine.gemm(&attended, &weights.wo)?);
    let after_attention = residual_add(x, &projected)?;
    let ff_normed = rms_norm(&after_attention);
    let hidden = gate(&requantize(&engine.gemm(&ff_normed, &weights.w1)?));
    let ff_out = requantize(&engine.gemm(&hidden, &weights.w2)?);
    residual_add(&after_attention, &ff_out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::PADDING_BUCKET;

    const SEED: [u8; 32] = [21u8; 32];

    #[test]
    fn split_block_matches_plaintext_reference_bit_for_bit() {
        let x = deterministic_input(&SEED);
        let weights = deterministic_weights(&SEED);
        let reference = transformer_block(&x, &weights, &mut PlainEngine).unwrap();
        let mut engine = BesiSplitEngine::new(&SEED);
        let sealed = transformer_block(&x, &weights, &mut engine).unwrap();
        assert_eq!(reference, sealed);
        assert_eq!(engine.remote_gemms, 6);
        // Different split randomness, identical result: sharing never leaks into the output.
        let mut other = BesiSplitEngine::new(&[99u8; 32]);
        assert_eq!(
            transformer_block(&x, &weights, &mut other).unwrap(),
            reference
        );
        // The output is a real computation, not a fixed point of the input.
        assert_ne!(reference, x);
    }

    #[test]
    fn every_remote_gemm_is_padded_to_the_public_bucket() {
        assert_eq!(PADDING_BUCKET, 128);
        let (padded, true_rows) = pad_rows(&deterministic_input(&SEED)).unwrap();
        assert_eq!(padded.rows, PADDING_BUCKET);
        assert_eq!(true_rows, SEQ);
    }

    #[test]
    fn falsifier_tampered_executor_share_rejects_before_slicing_on_every_gemm() {
        let x = deterministic_input(&SEED);
        let weights = deterministic_weights(&SEED);
        for target in 0..6u32 {
            let mut engine = BesiSplitEngine::new(&SEED);
            engine.tamper_gemm = Some(target);
            assert_eq!(
                transformer_block(&x, &weights, &mut engine),
                Err(BesiError::FreivaldsMismatch),
                "tampered remote GEMM {target} must fail the exact-Z check"
            );
        }
    }

    #[test]
    fn falsifier_slicing_is_impossible_without_verification() {
        let y = Matrix::new(PADDING_BUCKET, 2, vec![0u64; PADDING_BUCKET * 2]).unwrap();
        assert_eq!(
            slice_after_verification(&y, 1, false),
            Err(BesiError::FreivaldsMismatch)
        );
    }
}
