//! Frozen mini W8A8 integer decoder profile: reference forward pass,
//! token-state chain, activation-DA commitments, KV replay, chunk-Freivalds
//! layer verification, dispute bisection, and the integer sampler.
//!
//! This module is the local, executable form of N-PROFILE, N-TOKEN-STATE,
//! N-CHUNK-FREIVALDS, N-BISECT, N-ACT-DA, N-KV-REPLAY, and N-SAMPLER at a
//! miniature shape (hidden 32, 2 layers, GQA 4q/2kv, head_dim 8, MLP 64,
//! vocab 64). Every operation is exact integer arithmetic with pinned
//! rounding, saturation, and tie laws; the committed tables live in
//! [`crate::luts`]; the profile is frozen by `protocol/vectors/nel/`
//! `forward-w8a8-v1.json`. Nothing here claims GPU or 0.5B-scale evidence:
//! the cross-vendor conformance campaign (E-NEL-01) and real-prover costs
//! (E-NEL-06) remain external.

use crate::luts::{EXP2_Q15, ROPE_COS_Q15, ROPE_SIN_Q15, SILU_I8};
use crate::{
    domain_hash, freivalds_verify_u64, FreivaldsProfile, Hash32, NelError, TokenStateCommitment,
    Verdict,
};

/// Residual-stream width.
pub const HIDDEN: usize = 32;
/// Transformer layer count.
pub const LAYERS: usize = 2;
/// Query heads.
pub const Q_HEADS: usize = 4;
/// KV heads (GQA groups).
pub const KV_HEADS: usize = 2;
/// Per-head dimension.
pub const HEAD_DIM: usize = 8;
/// MLP inner width.
pub const MLP: usize = 64;
/// Vocabulary size.
pub const VOCAB: usize = 64;
/// Maximum context (bounded by the committed RoPE table).
pub const MAX_CONTEXT: usize = 64;
/// Fused QKV output width: (Q_HEADS + 2 * KV_HEADS) * HEAD_DIM.
pub const QKV_DIM: usize = (Q_HEADS + 2 * KV_HEADS) * HEAD_DIM;
/// Committed ops per transformer layer (see [`ops`]).
pub const OPS_PER_LAYER: u16 = 14;
/// Committed ops in the virtual finalization layer (see [`ops`]).
pub const FINAL_OPS: u16 = 3;

/// Pinned requant constants `(mult, shift)` and scale laws. A change to any
/// of these is a new `numeric_profile_id`.
pub mod scales {
    /// QKV projection requant.
    pub const QKV: (i64, u32) = (1, 11);
    /// Attention output projection requant.
    pub const OUT: (i64, u32) = (1, 11);
    /// MLP gate/up projection requant.
    pub const GATE_UP: (i64, u32) = (1, 11);
    /// MLP down projection requant.
    pub const DOWN: (i64, u32) = (1, 12);
    /// P·V attention value requant (int16 `P` operand).
    pub const PV: (i64, u32) = (1, 15);
    /// SiLU(gate)·up elementwise product shift.
    pub const MLP_PROD_SHIFT: u32 = 8;
    /// RMSNorm output shift (gamma and `1/sqrt(d)` folded).
    pub const RMS_SHIFT: u32 = 31;
    /// Attention score pre-shift feeding the Q6 log2-domain softmax
    /// (folds the `1/sqrt(head_dim)` temperature).
    pub const SCORE_SHIFT: u32 = 7;
}

/// Committed operation indices inside a layer and the virtual final layer.
pub mod ops {
    /// Pre-attention RMSNorm.
    pub const RMS1: u16 = 0;
    /// Fused QKV GEMM (accumulators are the Freivalds surface).
    pub const QKV: u16 = 1;
    /// RoPE rotate-half on Q and K heads.
    pub const ROPE: u16 = 2;
    /// Q·Kᵀ score GEMMs (one record per query head).
    pub const SCORES: u16 = 3;
    /// Integer softmax rows.
    pub const SOFTMAX: u16 = 4;
    /// P·V GEMMs (one record per query head).
    pub const PV: u16 = 5;
    /// Attention output projection GEMM.
    pub const OUT: u16 = 6;
    /// Post-attention saturating residual add.
    pub const RESIDUAL1: u16 = 7;
    /// Pre-MLP RMSNorm.
    pub const RMS2: u16 = 8;
    /// MLP gate GEMM.
    pub const GATE: u16 = 9;
    /// MLP up GEMM.
    pub const UP: u16 = 10;
    /// SiLU LUT + elementwise product + requant.
    pub const SILU_MUL: u16 = 11;
    /// MLP down GEMM.
    pub const DOWN: u16 = 12;
    /// Post-MLP saturating residual add.
    pub const RESIDUAL2: u16 = 13;
    /// Virtual final layer: final RMSNorm.
    pub const FINAL_RMS: u16 = 0;
    /// Virtual final layer: LM head GEMM (INT32 logits, no requant).
    pub const LM_HEAD: u16 = 1;
    /// Virtual final layer: token selection (greedy or sampler).
    pub const SELECT: u16 = 2;
}

/// Additional domain strings for the inference surface.
pub mod domains {
    /// Committed LUT bundle root.
    pub const LUT: &str = "NOOS/NEL/LUT/V1";
    /// Mini profile identity.
    pub const PROFILE: &str = "NOOS/NEL/PROFILE/MINI-W8A8/V1";
    /// Deterministic test-model weight stream.
    pub const WEIGHTS: &str = "NOOS/NEL/TESTMODEL/W8A8/V1";
    /// Merkle interior node.
    pub const MERKLE_NODE: &str = "NOOS/NEL/MERKLE/NODE/V1";
    /// Token-history leaf.
    pub const HISTORY_LEAF: &str = "NOOS/NEL/HISTORY/LEAF/V1";
    /// Activation-DA leaf.
    pub const ACT_LEAF: &str = "NOOS/NEL/ACT/LEAF/V1";
    /// Per-op commitment.
    pub const OP: &str = "NOOS/NEL/OP/V1";
    /// Per-layer output commitment.
    pub const LAYER: &str = "NOOS/NEL/LAYER/V1";
    /// Logical KV commitment.
    pub const KV: &str = "NOOS/NEL/KV/V1";
    /// Sampler draw derivation.
    pub const DRAW: &str = "NOOS/NEL/DRAW/V1";
    /// Freivalds challenge-vector derivation.
    pub const FREIVALDS_CHALLENGE: &str = "NOOS/NEL/FREIVALDS/CHALLENGE/V1";
}

// ---------------------------------------------------------------------------
// Integer primitives (pinned laws)
// ---------------------------------------------------------------------------

/// Saturate to `[-128, 127]`.
#[must_use]
pub fn sat8(v: i64) -> i8 {
    v.clamp(i64::from(i8::MIN), i64::from(i8::MAX)) as i8
}

/// Saturating int8 residual add (documented profile simplification).
#[must_use]
pub fn sat_add8(a: i8, b: i8) -> i8 {
    a.saturating_add(b)
}

/// Pinned dyadic requant: `q = sat8((acc * mult + 2^(shift-1)) >> shift)` —
/// the exact floor-quotient round-half-up identity. `shift >= 1`.
///
/// Bounds: callers keep `|acc * mult| < 2^62` (the G8 accumulator lemma in
/// [`gemm_i8`]/[`gemm_pv`] bounds every accumulator below `2^31`), so the
/// widening arithmetic cannot overflow i64.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn requant(acc: i64, mult: i64, shift: u32) -> i8 {
    debug_assert!((1..63).contains(&shift));
    sat8((acc * mult + (1i64 << (shift - 1))) >> shift)
}

/// Pinned integer square root: seed `2^ceil(bits/2)`, exactly 8 Newton
/// steps, 2 fixed correction steps. Gated equal to `floor(sqrt(v))` in tests.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn isqrt_pinned(v: u64) -> u64 {
    if v == 0 {
        return 0;
    }
    let bits = 64u32 - v.leading_zeros();
    let mut x = 1u64 << bits.div_ceil(2);
    for _ in 0..8 {
        x = (x + v / x) >> 1;
        if x == 0 {
            x = 1;
        }
    }
    for _ in 0..2 {
        if (x + 1).checked_mul(x + 1).is_some_and(|sq| sq <= v) {
            x += 1;
        } else if x.checked_mul(x).is_none_or(|sq| sq > v) {
            x -= 1;
        }
    }
    x
}

/// INT8×INT8→INT32 GEMM with the G8 accumulator non-overflow lemma checked
/// at the shape boundary: `k * 127 * 127 < 2^31` or the shape is
/// unregistrable ([`NelError::ArithmeticOverflow`]). Accumulators never
/// saturate; saturation exists only at requant boundaries.
#[allow(clippy::arithmetic_side_effects)]
pub fn gemm_i8(a: &[i8], b: &[i8], m: usize, k: usize, n: usize) -> Result<Vec<i32>, NelError> {
    let (ak, bk, ck) = (
        m.checked_mul(k).ok_or(NelError::ArithmeticOverflow)?,
        k.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?,
        m.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?,
    );
    if a.len() != ak || b.len() != bk || k == 0 {
        return Err(NelError::InvalidCount);
    }
    if i64::try_from(k).map_err(|_| NelError::ArithmeticOverflow)? * 127 * 127 >= 1i64 << 31 {
        return Err(NelError::ArithmeticOverflow);
    }
    let mut c = vec![0i32; ck];
    for row in 0..m {
        for col in 0..n {
            let mut acc = 0i32;
            for x in 0..k {
                acc += i32::from(a[row * k + x]) * i32::from(b[x * n + col]);
            }
            c[row * n + col] = acc;
        }
    }
    Ok(c)
}

/// INT16×INT8→INT32 GEMM for the P·V leaf (the int16 softmax cap is
/// load-bearing): lemma `k * 32767 * 127 < 2^31`.
#[allow(clippy::arithmetic_side_effects)]
pub fn gemm_pv(p: &[i16], v: &[i8], m: usize, k: usize, n: usize) -> Result<Vec<i32>, NelError> {
    let (ak, bk, ck) = (
        m.checked_mul(k).ok_or(NelError::ArithmeticOverflow)?,
        k.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?,
        m.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?,
    );
    if p.len() != ak || v.len() != bk || k == 0 {
        return Err(NelError::InvalidCount);
    }
    if i64::try_from(k).map_err(|_| NelError::ArithmeticOverflow)? * 32_767 * 127 >= 1i64 << 31 {
        return Err(NelError::ArithmeticOverflow);
    }
    let mut c = vec![0i32; ck];
    for row in 0..m {
        for col in 0..n {
            let mut acc = 0i32;
            for x in 0..k {
                acc += i32::from(p[row * k + x]) * i32::from(v[x * n + col]);
            }
            c[row * n + col] = acc;
        }
    }
    Ok(c)
}

/// Pinned integer RMSNorm: exact sum of squares, `S+1` epsilon, pinned
/// [`isqrt_pinned`], `isr = floor(2^30 / z)`, INT64 scale with gamma and
/// round-half-up shift [`scales::RMS_SHIFT`].
#[allow(clippy::arithmetic_side_effects)]
pub fn rmsnorm(x: &[i8], gamma: &[i8]) -> Result<Vec<i8>, NelError> {
    if x.is_empty() || x.len() != gamma.len() {
        return Err(NelError::InvalidCount);
    }
    let ss: i64 = x.iter().map(|&v| i64::from(v) * i64::from(v)).sum();
    let ms = ss / i64::try_from(x.len()).map_err(|_| NelError::ArithmeticOverflow)?;
    let z = isqrt_pinned(u64::try_from(ms).map_err(|_| NelError::ArithmeticOverflow)? + 1).max(1);
    let isr = (1i64 << 30) / i64::try_from(z).map_err(|_| NelError::ArithmeticOverflow)?;
    Ok(x.iter()
        .zip(gamma)
        .map(|(&v, &g)| {
            sat8(
                (i64::from(v) * isr * i64::from(g) + (1i64 << (scales::RMS_SHIFT - 1)))
                    >> scales::RMS_SHIFT,
            )
        })
        .collect())
}

/// Pinned integer softmax row: INT32 scores in, Q1.15 `P` out. Integer
/// stable-max, [`scales::SCORE_SHIFT`] temperature, Q6 log2-domain exponent
/// via the committed [`EXP2_Q15`] table, masked entries pinned to 0, one
/// exact integer division per row, `P_j = min((e_j*R + 2^14) >> 15, 32767)`.
#[allow(clippy::arithmetic_side_effects)]
pub fn softmax_q15(scores: &[i32], visible: usize) -> Result<Vec<i16>, NelError> {
    if visible == 0 || visible > scores.len() {
        return Err(NelError::InvalidCount);
    }
    let m = i64::from(
        *scores
            .get(..visible)
            .and_then(|s| s.iter().max())
            .ok_or(NelError::InvalidCount)?,
    );
    let mut e = vec![0u64; scores.len()];
    for (j, slot) in e.iter_mut().enumerate().take(visible) {
        let d = (m - i64::from(scores[j])) >> scales::SCORE_SHIFT;
        let ip = d >> 6;
        let fr = usize::try_from(d & 63).map_err(|_| NelError::ArithmeticOverflow)?;
        *slot = if ip >= 16 {
            0
        } else {
            u64::from(EXP2_Q15[fr])
                >> u32::try_from(ip).map_err(|_| NelError::ArithmeticOverflow)?
        };
    }
    let tot: u64 = e.iter().sum();
    if tot == 0 {
        return Err(NelError::ArithmeticOverflow);
    }
    let r = (1u64 << 30) / tot;
    Ok(e.iter()
        .map(|&ej| ((ej * r + (1u64 << 14)) >> 15).min(32_767) as i16)
        .collect())
}

/// Pinned rotate-half RoPE on one head at one position: committed Q1.15
/// tables, round-half-up Q15 products, sat8.
#[allow(clippy::arithmetic_side_effects)]
pub fn rope_rotate_head(head: &mut [i8], position: usize) -> Result<(), NelError> {
    if head.len() != HEAD_DIM || position >= MAX_CONTEXT {
        return Err(NelError::InvalidCount);
    }
    let half = HEAD_DIM / 2;
    for i in 0..half {
        let c = i64::from(ROPE_COS_Q15[position * half + i]);
        let s = i64::from(ROPE_SIN_Q15[position * half + i]);
        let x1 = i64::from(head[i]);
        let x2 = i64::from(head[i + half]);
        head[i] = sat8((x1 * c - x2 * s + (1i64 << 14)) >> 15);
        head[i + half] = sat8((x1 * s + x2 * c + (1i64 << 14)) >> 15);
    }
    Ok(())
}

/// SiLU epilogue: committed 256-byte LUT, then
/// `sat8((silu * up + 2^(shift-1)) >> shift)` with [`scales::MLP_PROD_SHIFT`].
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn silu_mul(gate: i8, up: i8) -> i8 {
    let s = i64::from(SILU_I8[usize::from(gate.cast_unsigned())]);
    requant(s * i64::from(up), 1, scales::MLP_PROD_SHIFT)
}

/// Committed LUT bundle root: the bytes of every activation table, in pinned
/// order, under one domain.
#[must_use]
pub fn lut_root() -> Hash32 {
    let mut body = Vec::new();
    for e in EXP2_Q15 {
        body.extend(e.to_le_bytes());
    }
    for e in SILU_I8 {
        body.extend(e.to_le_bytes());
    }
    for e in ROPE_COS_Q15 {
        body.extend(e.to_le_bytes());
    }
    for e in ROPE_SIN_Q15 {
        body.extend(e.to_le_bytes());
    }
    domain_hash(domains::LUT, &body)
}

/// The mini profile identity: LUT bundle root plus every pinned scale
/// constant and shape. Any semantic change is a new profile.
#[must_use]
pub fn mini_profile_id() -> Hash32 {
    let mut body = Vec::new();
    body.extend(lut_root());
    for c in [
        scales::QKV.0,
        i64::from(scales::QKV.1),
        scales::OUT.0,
        i64::from(scales::OUT.1),
        scales::GATE_UP.0,
        i64::from(scales::GATE_UP.1),
        scales::DOWN.0,
        i64::from(scales::DOWN.1),
        scales::PV.0,
        i64::from(scales::PV.1),
        i64::from(scales::MLP_PROD_SHIFT),
        i64::from(scales::RMS_SHIFT),
        i64::from(scales::SCORE_SHIFT),
    ] {
        body.extend(c.to_le_bytes());
    }
    for d in [
        HIDDEN,
        LAYERS,
        Q_HEADS,
        KV_HEADS,
        HEAD_DIM,
        MLP,
        VOCAB,
        MAX_CONTEXT,
    ] {
        body.extend((d as u64).to_le_bytes());
    }
    domain_hash(domains::PROFILE, &body)
}

// ---------------------------------------------------------------------------
// Merkle (pad-to-power-of-two, pinned)
// ---------------------------------------------------------------------------

/// Merkle root over 32-byte leaves: pad to the next power of two with
/// all-zero leaves; interior node = `H(MERKLE_NODE, left || right)`.
#[must_use]
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return [0; 32];
    }
    let mut level: Vec<Hash32> = leaves.to_vec();
    let width = leaves.len().next_power_of_two();
    level.resize(width, [0; 32]);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let mut body = Vec::with_capacity(64);
                body.extend(pair[0]);
                body.extend(pair[1]);
                domain_hash(domains::MERKLE_NODE, &body)
            })
            .collect();
    }
    level[0]
}

/// Merkle inclusion proof (sibling per level, leaf-to-root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Leaf index.
    pub index: u32,
    /// Sibling hashes, leaf level first.
    pub path: Vec<Hash32>,
}

/// Open leaf `index` against the padded tree over `leaves`.
pub fn merkle_open(leaves: &[Hash32], index: usize) -> Result<MerkleProof, NelError> {
    if index >= leaves.len() {
        return Err(NelError::WrongPosition);
    }
    let mut level: Vec<Hash32> = leaves.to_vec();
    level.resize(leaves.len().next_power_of_two(), [0; 32]);
    let mut path = Vec::new();
    let mut i = index;
    while level.len() > 1 {
        path.push(level[i ^ 1]);
        level = level
            .chunks(2)
            .map(|pair| {
                let mut body = Vec::with_capacity(64);
                body.extend(pair[0]);
                body.extend(pair[1]);
                domain_hash(domains::MERKLE_NODE, &body)
            })
            .collect();
        i /= 2;
    }
    Ok(MerkleProof {
        index: u32::try_from(index).map_err(|_| NelError::ArithmeticOverflow)?,
        path,
    })
}

/// Verify a Merkle inclusion proof against `root`.
#[must_use]
pub fn merkle_verify(root: &Hash32, leaf: &Hash32, proof: &MerkleProof) -> bool {
    let mut acc = *leaf;
    let mut i = proof.index;
    for sib in &proof.path {
        let mut body = Vec::with_capacity(64);
        if i & 1 == 0 {
            body.extend(acc);
            body.extend(sib);
        } else {
            body.extend(sib);
            body.extend(acc);
        }
        acc = domain_hash(domains::MERKLE_NODE, &body);
        i >>= 1;
    }
    i == 0 && acc == *root
}

/// Token-history root: Merkle over per-token leaves
/// `H(HISTORY_LEAF, position || token_id)`.
#[must_use]
pub fn token_history_root(tokens: &[u32]) -> Hash32 {
    let leaves: Vec<Hash32> = tokens
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut body = Vec::with_capacity(8);
            body.extend((i as u32).to_le_bytes());
            body.extend(t.to_le_bytes());
            domain_hash(domains::HISTORY_LEAF, &body)
        })
        .collect();
    merkle_root(&leaves)
}

// ---------------------------------------------------------------------------
// Deterministic mini model (N-PROFILE reference shape)
// ---------------------------------------------------------------------------

/// One layer's weights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerWeights {
    /// Pre-attention RMSNorm gamma (positive i8).
    pub gamma1: Vec<i8>,
    /// Fused QKV weight, `HIDDEN x QKV_DIM` row-major.
    pub wqkv: Vec<i8>,
    /// Output projection, `HIDDEN x HIDDEN`.
    pub wout: Vec<i8>,
    /// Pre-MLP RMSNorm gamma.
    pub gamma2: Vec<i8>,
    /// Gate projection, `HIDDEN x MLP`.
    pub wgate: Vec<i8>,
    /// Up projection, `HIDDEN x MLP`.
    pub wup: Vec<i8>,
    /// Down projection, `MLP x HIDDEN`.
    pub wdown: Vec<i8>,
}

/// The deterministic mini model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiniModel {
    /// Token embedding, `VOCAB x HIDDEN`.
    pub embed: Vec<i8>,
    /// Transformer layers.
    pub layers: Vec<LayerWeights>,
    /// Final RMSNorm gamma.
    pub final_gamma: Vec<i8>,
    /// LM head, `HIDDEN x VOCAB`.
    pub lm_head: Vec<i8>,
}

fn tensor_stream(name: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(domains::WEIGHTS.as_bytes());
    h.update(name.as_bytes());
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

/// Bounded signed weights in `[-47, 47]` from the pinned byte stream.
fn tensor_i8(name: &str, len: usize) -> Vec<i8> {
    tensor_stream(name, len)
        .into_iter()
        .map(|b| (i16::from(b) % 95).wrapping_sub(47) as i8)
        .collect()
}

/// Positive gammas in `[16, 47]`.
fn tensor_gamma(name: &str, len: usize) -> Vec<i8> {
    tensor_stream(name, len)
        .into_iter()
        .map(|b| (i16::from(b) % 32).wrapping_add(16) as i8)
        .collect()
}

fn bytes_of_i8(v: &[i8]) -> Vec<u8> {
    v.iter().map(|&x| x.cast_unsigned()).collect()
}

impl MiniModel {
    /// The deterministic reference model: every tensor derives from the
    /// pinned [`domains::WEIGHTS`] stream keyed by tensor name.
    #[must_use]
    pub fn deterministic() -> Self {
        let layers = (0..LAYERS)
            .map(|l| LayerWeights {
                gamma1: tensor_gamma(&format!("layer{l}.gamma1"), HIDDEN),
                wqkv: tensor_i8(&format!("layer{l}.wqkv"), HIDDEN * QKV_DIM),
                wout: tensor_i8(&format!("layer{l}.wout"), HIDDEN * HIDDEN),
                gamma2: tensor_gamma(&format!("layer{l}.gamma2"), HIDDEN),
                wgate: tensor_i8(&format!("layer{l}.wgate"), HIDDEN * MLP),
                wup: tensor_i8(&format!("layer{l}.wup"), HIDDEN * MLP),
                wdown: tensor_i8(&format!("layer{l}.wdown"), MLP * HIDDEN),
            })
            .collect();
        Self {
            embed: tensor_i8("embed", VOCAB * HIDDEN),
            layers,
            final_gamma: tensor_gamma("final_gamma", HIDDEN),
            lm_head: tensor_i8("lm_head", HIDDEN * VOCAB),
        }
    }

    /// Merkle root over per-tensor content hashes, in pinned order.
    #[must_use]
    pub fn weight_root(&self) -> Hash32 {
        let mut leaves = Vec::new();
        let mut leaf = |name: &str, bytes: &[i8]| {
            let mut body = name.as_bytes().to_vec();
            body.extend(bytes_of_i8(bytes));
            leaves.push(domain_hash(domains::WEIGHTS, &body));
        };
        leaf("embed", &self.embed);
        for (l, w) in self.layers.iter().enumerate() {
            leaf(&format!("layer{l}.gamma1"), &w.gamma1);
            leaf(&format!("layer{l}.wqkv"), &w.wqkv);
            leaf(&format!("layer{l}.wout"), &w.wout);
            leaf(&format!("layer{l}.gamma2"), &w.gamma2);
            leaf(&format!("layer{l}.wgate"), &w.wgate);
            leaf(&format!("layer{l}.wup"), &w.wup);
            leaf(&format!("layer{l}.wdown"), &w.wdown);
        }
        leaf("final_gamma", &self.final_gamma);
        leaf("lm_head", &self.lm_head);
        merkle_root(&leaves)
    }

    /// Canonical byte stream for local full-weight availability exercises.
    /// Tensor order is identical to [`Self::weight_root`]; this is a mini
    /// profile precursor, not the external 0.5B weight artifact required by
    /// E-NEL-05.
    #[must_use]
    pub fn canonical_weight_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(bytes_of_i8(&self.embed));
        for layer in &self.layers {
            out.extend(bytes_of_i8(&layer.gamma1));
            out.extend(bytes_of_i8(&layer.wqkv));
            out.extend(bytes_of_i8(&layer.wout));
            out.extend(bytes_of_i8(&layer.gamma2));
            out.extend(bytes_of_i8(&layer.wgate));
            out.extend(bytes_of_i8(&layer.wup));
            out.extend(bytes_of_i8(&layer.wdown));
        }
        out.extend(bytes_of_i8(&self.final_gamma));
        out.extend(bytes_of_i8(&self.lm_head));
        out
    }

    /// Resolve a weight-side Freivalds `B` operand.
    pub fn weight_i64(&self, id: WeightId) -> Result<Vec<i64>, NelError> {
        let slice = match id {
            WeightId::Qkv(l) => {
                &self
                    .layers
                    .get(usize::from(l))
                    .ok_or(NelError::WrongPosition)?
                    .wqkv
            }
            WeightId::Out(l) => {
                &self
                    .layers
                    .get(usize::from(l))
                    .ok_or(NelError::WrongPosition)?
                    .wout
            }
            WeightId::Gate(l) => {
                &self
                    .layers
                    .get(usize::from(l))
                    .ok_or(NelError::WrongPosition)?
                    .wgate
            }
            WeightId::Up(l) => {
                &self
                    .layers
                    .get(usize::from(l))
                    .ok_or(NelError::WrongPosition)?
                    .wup
            }
            WeightId::Down(l) => {
                &self
                    .layers
                    .get(usize::from(l))
                    .ok_or(NelError::WrongPosition)?
                    .wdown
            }
            WeightId::LmHead => &self.lm_head,
        };
        Ok(slice.iter().map(|&x| i64::from(x)).collect())
    }
}

// ---------------------------------------------------------------------------
// KV cache and commitment (N-KV-REPLAY)
// ---------------------------------------------------------------------------

/// Per-layer KV store: roped K and raw V rows, one per position, each
/// `KV_HEADS * HEAD_DIM` wide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerKv {
    /// Roped key rows.
    pub k: Vec<Vec<i8>>,
    /// Value rows.
    pub v: Vec<Vec<i8>>,
}

/// The logical KV state: recomputable from the committed token prefix; an
/// executor checkpoint is an untrusted accelerator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvCache {
    /// One store per layer.
    pub layers: Vec<LayerKv>,
}

impl Default for KvCache {
    fn default() -> Self {
        Self {
            layers: vec![LayerKv::default(); LAYERS],
        }
    }
}

impl KvCache {
    /// Positions currently cached.
    #[must_use]
    pub fn positions(&self) -> usize {
        self.layers.first().map_or(0, |l| l.k.len())
    }

    /// Logical KV commitment bound to
    /// `(model_root, profile, job_id, position)` — the digest §8 key rule.
    #[must_use]
    pub fn commitment(&self, model_root: &Hash32, profile: &Hash32, job_id: &Hash32) -> Hash32 {
        let mut body = Vec::new();
        body.extend(model_root);
        body.extend(profile);
        body.extend(job_id);
        body.extend((self.positions() as u32).to_le_bytes());
        for layer in &self.layers {
            for row in &layer.k {
                body.extend(bytes_of_i8(row));
            }
            for row in &layer.v {
                body.extend(bytes_of_i8(row));
            }
        }
        domain_hash(domains::KV, &body)
    }
}

// ---------------------------------------------------------------------------
// Forward pass with committed trace (N-PROFILE + N-ACT-DA surfaces)
// ---------------------------------------------------------------------------

/// Weight-side operand identity for chunk-Freivalds (fixed `B` across the
/// chunk — the `W·r` term amortizes over T).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightId {
    /// Fused QKV weight of a layer.
    Qkv(u16),
    /// Output projection of a layer.
    Out(u16),
    /// Gate projection of a layer.
    Gate(u16),
    /// Up projection of a layer.
    Up(u16),
    /// Down projection of a layer.
    Down(u16),
    /// LM head.
    LmHead,
}

/// Freivalds `B` operand: a fixed model weight or an inline (cache-side)
/// matrix, both committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BOperand {
    /// Model weight reference.
    Weight(WeightId),
    /// Inline committed matrix (attention score/PV cache operands).
    Inline(Vec<i64>),
}

/// One committed GEMM: inputs, operand identity, and INT32 accumulators
/// (the C32 Freivalds surface, recorded pre-requant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatMulRecord {
    /// Layer index (== [`LAYERS`] for the virtual final layer).
    pub layer: u16,
    /// Op index within the layer.
    pub op: u16,
    /// Head index for per-head attention records; 0 otherwise.
    pub head: u8,
    /// Rows of `A`.
    pub m: usize,
    /// Inner dimension.
    pub k: usize,
    /// Columns of `B`.
    pub n: usize,
    /// `A`, sign-extended.
    pub a: Vec<i64>,
    /// `B` operand.
    pub b: BOperand,
    /// `C32` accumulators, sign-extended.
    pub c: Vec<i64>,
}

/// A deliberate single-op corruption for falsifier tests: a cheating
/// executor that computes honestly, corrupts exactly one committed op, and
/// propagates downstream consistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tamper {
    /// Forward position (grid token axis).
    pub position: u32,
    /// Layer index (== [`LAYERS`] for the virtual final layer).
    pub layer: u16,
    /// Op index.
    pub op: u16,
    /// Wrapping delta applied to element 0 of the op output (the INT32
    /// accumulator for GEMM ops; truncated to the element width for
    /// nonlinear payloads).
    pub delta: i32,
}

/// Everything one forward step commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepTrace {
    /// Absolute position fed.
    pub position: u32,
    /// Residual stream after each layer (the activation-DA bytes).
    pub layer_outputs: Vec<Vec<i8>>,
    /// Canonical payload bytes per `[layer][op]` (virtual layer last).
    pub op_payloads: Vec<Vec<Vec<u8>>>,
    /// Committed GEMM records.
    pub matmuls: Vec<MatMulRecord>,
    /// INT32 logits.
    pub logits: Vec<i32>,
}

/// Canonical committed bytes of a GEMM op: the INT32 accumulators (the C32
/// Freivalds/dispute surface, exactly what the harness transcript commits)
/// followed by the requanted output.
fn gemm_payload(c32: &[i32], out: &[i8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(c32.len().saturating_mul(4).saturating_add(out.len()));
    for x in c32 {
        v.extend(x.to_le_bytes());
    }
    v.extend(bytes_of_i8(out));
    v
}

fn tamper_c32(c: &mut [i32], tamper: Option<&Tamper>, position: u32, layer: u16, op: u16) {
    if let Some(t) = tamper {
        if t.position == position && t.layer == layer && t.op == op {
            if let Some(first) = c.first_mut() {
                *first = first.wrapping_add(t.delta);
            }
        }
    }
}

fn tamper_bytes(bytes: &mut [i8], tamper: Option<&Tamper>, position: u32, layer: u16, op: u16) {
    if let Some(t) = tamper {
        if t.position == position && t.layer == layer && t.op == op {
            if let Some(first) = bytes.first_mut() {
                *first = first.wrapping_add(t.delta as i8);
            }
        }
    }
}

/// One forward step of the frozen mini profile. Records every committed op
/// payload and GEMM accumulator. `tamper` injects the cheating-executor
/// fault model for falsifier tests; `None` is the honest executor.
#[allow(clippy::arithmetic_side_effects, clippy::too_many_lines)]
pub fn forward_token(
    model: &MiniModel,
    cache: &mut KvCache,
    position: u32,
    token_id: u32,
    tamper: Option<&Tamper>,
) -> Result<StepTrace, NelError> {
    let pos = usize::try_from(position).map_err(|_| NelError::ArithmeticOverflow)?;
    if pos >= MAX_CONTEXT || pos != cache.positions() {
        return Err(NelError::WrongPosition);
    }
    let tok = usize::try_from(token_id).map_err(|_| NelError::ArithmeticOverflow)?;
    if tok >= VOCAB || cache.layers.len() != LAYERS {
        return Err(NelError::InvalidCount);
    }
    let mut x: Vec<i8> = model.embed[tok * HIDDEN..(tok + 1) * HIDDEN].to_vec();
    let mut layer_outputs = Vec::with_capacity(LAYERS);
    let mut op_payloads: Vec<Vec<Vec<u8>>> = Vec::with_capacity(LAYERS + 1);
    let mut matmuls = Vec::new();

    for (l, w) in model.layers.iter().enumerate() {
        let layer = u16::try_from(l).map_err(|_| NelError::ArithmeticOverflow)?;
        let mut payloads: Vec<Vec<u8>> = vec![Vec::new(); usize::from(OPS_PER_LAYER)];

        // op 0: pre-attention RMSNorm
        let mut h1 = rmsnorm(&x, &w.gamma1)?;
        tamper_bytes(&mut h1, tamper, position, layer, ops::RMS1);
        payloads[usize::from(ops::RMS1)] = bytes_of_i8(&h1);

        // op 1: fused QKV GEMM (C32 committed)
        let mut qkv_c = gemm_i8(&h1, &w.wqkv, 1, HIDDEN, QKV_DIM)?;
        tamper_c32(&mut qkv_c, tamper, position, layer, ops::QKV);
        matmuls.push(MatMulRecord {
            layer,
            op: ops::QKV,
            head: 0,
            m: 1,
            k: HIDDEN,
            n: QKV_DIM,
            a: h1.iter().map(|&v| i64::from(v)).collect(),
            b: BOperand::Weight(WeightId::Qkv(layer)),
            c: qkv_c.iter().map(|&v| i64::from(v)).collect(),
        });
        let qkv: Vec<i8> = qkv_c
            .iter()
            .map(|&acc| requant(i64::from(acc), scales::QKV.0, scales::QKV.1))
            .collect();
        payloads[usize::from(ops::QKV)] = gemm_payload(&qkv_c, &qkv);

        // op 2: RoPE on Q and K heads
        let mut q = qkv[..Q_HEADS * HEAD_DIM].to_vec();
        let mut k_row = qkv[Q_HEADS * HEAD_DIM..(Q_HEADS + KV_HEADS) * HEAD_DIM].to_vec();
        let v_row = qkv[(Q_HEADS + KV_HEADS) * HEAD_DIM..].to_vec();
        for h in 0..Q_HEADS {
            rope_rotate_head(&mut q[h * HEAD_DIM..(h + 1) * HEAD_DIM], pos)?;
        }
        for h in 0..KV_HEADS {
            rope_rotate_head(&mut k_row[h * HEAD_DIM..(h + 1) * HEAD_DIM], pos)?;
        }
        let mut roped: Vec<i8> = q.iter().chain(k_row.iter()).copied().collect();
        tamper_bytes(&mut roped, tamper, position, layer, ops::ROPE);
        q = roped[..Q_HEADS * HEAD_DIM].to_vec();
        k_row = roped[Q_HEADS * HEAD_DIM..].to_vec();
        payloads[usize::from(ops::ROPE)] = bytes_of_i8(&roped);

        cache.layers[l].k.push(k_row);
        cache.layers[l].v.push(v_row);
        let ctx = pos + 1;

        // ops 3-5: per-head scores, softmax, PV
        let mut score_payload = Vec::new();
        let mut p_payload = Vec::new();
        let mut attn = vec![0i8; Q_HEADS * HEAD_DIM];
        let mut p_rows: Vec<Vec<i16>> = Vec::with_capacity(Q_HEADS);
        let mut score_rows: Vec<Vec<i32>> = Vec::with_capacity(Q_HEADS);
        for h in 0..Q_HEADS {
            let g = h / (Q_HEADS / KV_HEADS);
            // B = K-cache slice transposed to [HEAD_DIM x ctx]
            let mut kt = vec![0i8; HEAD_DIM * ctx];
            for (j, row) in cache.layers[l].k.iter().enumerate() {
                for i in 0..HEAD_DIM {
                    kt[i * ctx + j] = row[g * HEAD_DIM + i];
                }
            }
            let qh = &q[h * HEAD_DIM..(h + 1) * HEAD_DIM];
            let mut scores = gemm_i8(qh, &kt, 1, HEAD_DIM, ctx)?;
            tamper_c32(&mut scores, tamper, position, layer, ops::SCORES);
            matmuls.push(MatMulRecord {
                layer,
                op: ops::SCORES,
                head: u8::try_from(h).map_err(|_| NelError::ArithmeticOverflow)?,
                m: 1,
                k: HEAD_DIM,
                n: ctx,
                a: qh.iter().map(|&v| i64::from(v)).collect(),
                b: BOperand::Inline(kt.iter().map(|&v| i64::from(v)).collect()),
                c: scores.iter().map(|&v| i64::from(v)).collect(),
            });
            for s in &scores {
                score_payload.extend(s.to_le_bytes());
            }
            score_rows.push(scores);
        }
        payloads[usize::from(ops::SCORES)] = score_payload;
        for scores in &score_rows {
            let mut p = softmax_q15(scores, scores.len())?;
            if let Some(t) = tamper {
                if t.position == position && t.layer == layer && t.op == ops::SOFTMAX {
                    if let Some(first) = p.first_mut() {
                        *first = first.wrapping_add(t.delta as i16);
                    }
                }
            }
            for m in &p {
                p_payload.extend(m.to_le_bytes());
            }
            p_rows.push(p);
        }
        payloads[usize::from(ops::SOFTMAX)] = p_payload;
        let mut pv_payload = Vec::new();
        for (h, p) in p_rows.iter().enumerate() {
            let g = h / (Q_HEADS / KV_HEADS);
            let mut vm = vec![0i8; ctx * HEAD_DIM];
            for (j, row) in cache.layers[l].v.iter().enumerate() {
                vm[j * HEAD_DIM..(j + 1) * HEAD_DIM]
                    .copy_from_slice(&row[g * HEAD_DIM..(g + 1) * HEAD_DIM]);
            }
            let mut pv_c = gemm_pv(p, &vm, 1, ctx, HEAD_DIM)?;
            tamper_c32(&mut pv_c, tamper, position, layer, ops::PV);
            matmuls.push(MatMulRecord {
                layer,
                op: ops::PV,
                head: u8::try_from(h).map_err(|_| NelError::ArithmeticOverflow)?,
                m: 1,
                k: ctx,
                n: HEAD_DIM,
                a: p.iter().map(|&v| i64::from(v)).collect(),
                b: BOperand::Inline(vm.iter().map(|&v| i64::from(v)).collect()),
                c: pv_c.iter().map(|&v| i64::from(v)).collect(),
            });
            for &acc in &pv_c {
                pv_payload.extend(acc.to_le_bytes());
            }
            for (i, &acc) in pv_c.iter().enumerate() {
                attn[h * HEAD_DIM + i] = requant(i64::from(acc), scales::PV.0, scales::PV.1);
            }
            pv_payload.extend(bytes_of_i8(&attn[h * HEAD_DIM..(h + 1) * HEAD_DIM]));
        }
        payloads[usize::from(ops::PV)] = pv_payload;

        // op 6: output projection
        let mut out_c = gemm_i8(&attn, &w.wout, 1, HIDDEN, HIDDEN)?;
        tamper_c32(&mut out_c, tamper, position, layer, ops::OUT);
        matmuls.push(MatMulRecord {
            layer,
            op: ops::OUT,
            head: 0,
            m: 1,
            k: HIDDEN,
            n: HIDDEN,
            a: attn.iter().map(|&v| i64::from(v)).collect(),
            b: BOperand::Weight(WeightId::Out(layer)),
            c: out_c.iter().map(|&v| i64::from(v)).collect(),
        });
        let out: Vec<i8> = out_c
            .iter()
            .map(|&acc| requant(i64::from(acc), scales::OUT.0, scales::OUT.1))
            .collect();
        payloads[usize::from(ops::OUT)] = gemm_payload(&out_c, &out);

        // op 7: residual add
        let mut res1: Vec<i8> = x.iter().zip(&out).map(|(&a, &b)| sat_add8(a, b)).collect();
        tamper_bytes(&mut res1, tamper, position, layer, ops::RESIDUAL1);
        payloads[usize::from(ops::RESIDUAL1)] = bytes_of_i8(&res1);

        // op 8: pre-MLP RMSNorm
        let mut h2 = rmsnorm(&res1, &w.gamma2)?;
        tamper_bytes(&mut h2, tamper, position, layer, ops::RMS2);
        payloads[usize::from(ops::RMS2)] = bytes_of_i8(&h2);

        // ops 9-10: gate / up GEMMs
        let mut gate_c = gemm_i8(&h2, &w.wgate, 1, HIDDEN, MLP)?;
        tamper_c32(&mut gate_c, tamper, position, layer, ops::GATE);
        matmuls.push(MatMulRecord {
            layer,
            op: ops::GATE,
            head: 0,
            m: 1,
            k: HIDDEN,
            n: MLP,
            a: h2.iter().map(|&v| i64::from(v)).collect(),
            b: BOperand::Weight(WeightId::Gate(layer)),
            c: gate_c.iter().map(|&v| i64::from(v)).collect(),
        });
        let gate: Vec<i8> = gate_c
            .iter()
            .map(|&acc| requant(i64::from(acc), scales::GATE_UP.0, scales::GATE_UP.1))
            .collect();
        payloads[usize::from(ops::GATE)] = gemm_payload(&gate_c, &gate);
        let mut up_c = gemm_i8(&h2, &w.wup, 1, HIDDEN, MLP)?;
        tamper_c32(&mut up_c, tamper, position, layer, ops::UP);
        matmuls.push(MatMulRecord {
            layer,
            op: ops::UP,
            head: 0,
            m: 1,
            k: HIDDEN,
            n: MLP,
            a: h2.iter().map(|&v| i64::from(v)).collect(),
            b: BOperand::Weight(WeightId::Up(layer)),
            c: up_c.iter().map(|&v| i64::from(v)).collect(),
        });
        let up: Vec<i8> = up_c
            .iter()
            .map(|&acc| requant(i64::from(acc), scales::GATE_UP.0, scales::GATE_UP.1))
            .collect();
        payloads[usize::from(ops::UP)] = gemm_payload(&up_c, &up);

        // op 11: SiLU epilogue
        let mut act: Vec<i8> = gate
            .iter()
            .zip(&up)
            .map(|(&g, &u)| silu_mul(g, u))
            .collect();
        tamper_bytes(&mut act, tamper, position, layer, ops::SILU_MUL);
        payloads[usize::from(ops::SILU_MUL)] = bytes_of_i8(&act);

        // op 12: down GEMM
        let mut down_c = gemm_i8(&act, &w.wdown, 1, MLP, HIDDEN)?;
        tamper_c32(&mut down_c, tamper, position, layer, ops::DOWN);
        matmuls.push(MatMulRecord {
            layer,
            op: ops::DOWN,
            head: 0,
            m: 1,
            k: MLP,
            n: HIDDEN,
            a: act.iter().map(|&v| i64::from(v)).collect(),
            b: BOperand::Weight(WeightId::Down(layer)),
            c: down_c.iter().map(|&v| i64::from(v)).collect(),
        });
        let down: Vec<i8> = down_c
            .iter()
            .map(|&acc| requant(i64::from(acc), scales::DOWN.0, scales::DOWN.1))
            .collect();
        payloads[usize::from(ops::DOWN)] = gemm_payload(&down_c, &down);

        // op 13: residual add
        let mut res2: Vec<i8> = res1
            .iter()
            .zip(&down)
            .map(|(&a, &b)| sat_add8(a, b))
            .collect();
        tamper_bytes(&mut res2, tamper, position, layer, ops::RESIDUAL2);
        payloads[usize::from(ops::RESIDUAL2)] = bytes_of_i8(&res2);

        x = res2;
        layer_outputs.push(x.clone());
        op_payloads.push(payloads);
    }

    // Virtual finalization layer.
    let layer = u16::try_from(LAYERS).map_err(|_| NelError::ArithmeticOverflow)?;
    let mut payloads: Vec<Vec<u8>> = vec![Vec::new(); usize::from(FINAL_OPS)];
    let mut hf = rmsnorm(&x, &model.final_gamma)?;
    tamper_bytes(&mut hf, tamper, position, layer, ops::FINAL_RMS);
    payloads[usize::from(ops::FINAL_RMS)] = bytes_of_i8(&hf);
    let mut logits = gemm_i8(&hf, &model.lm_head, 1, HIDDEN, VOCAB)?;
    tamper_c32(&mut logits, tamper, position, layer, ops::LM_HEAD);
    matmuls.push(MatMulRecord {
        layer,
        op: ops::LM_HEAD,
        head: 0,
        m: 1,
        k: HIDDEN,
        n: VOCAB,
        a: hf.iter().map(|&v| i64::from(v)).collect(),
        b: BOperand::Weight(WeightId::LmHead),
        c: logits.iter().map(|&v| i64::from(v)).collect(),
    });
    let mut logits_payload = Vec::with_capacity(4 * VOCAB);
    for v in &logits {
        logits_payload.extend(v.to_le_bytes());
    }
    payloads[usize::from(ops::LM_HEAD)] = logits_payload;
    op_payloads.push(payloads);

    Ok(StepTrace {
        position,
        layer_outputs,
        op_payloads,
        matmuls,
        logits,
    })
}

// ---------------------------------------------------------------------------
// Lane run: token-state chain (N-TOKEN-STATE) + trace roots (N-ACT-DA)
// ---------------------------------------------------------------------------

/// Activation-DA leaf: `H(ACT_LEAF, job || position || layer || bytes)`.
#[must_use]
pub fn activation_leaf(job_id: &Hash32, position: u32, layer: u16, bytes: &[u8]) -> Hash32 {
    let mut body = Vec::with_capacity(bytes.len().saturating_add(38));
    body.extend(job_id);
    body.extend(position.to_le_bytes());
    body.extend(layer.to_le_bytes());
    body.extend(bytes);
    domain_hash(domains::ACT_LEAF, &body)
}

/// Per-op commitment: `H(OP, layer || op || payload)`.
#[must_use]
pub fn op_commitment(layer: u16, op: u16, payload: &[u8]) -> Hash32 {
    let mut body = Vec::with_capacity(payload.len().saturating_add(4));
    body.extend(layer.to_le_bytes());
    body.extend(op.to_le_bytes());
    body.extend(payload);
    domain_hash(domains::OP, &body)
}

/// One executed lane job: the full committed surface for claims, DA, replay,
/// and disputes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneRun {
    /// Job binding.
    pub job_id: Hash32,
    /// Model binding.
    pub model_root: Hash32,
    /// Numeric profile binding.
    pub profile_id: Hash32,
    /// Prompt length.
    pub prompt_len: usize,
    /// Prompt ‖ generated tokens.
    pub tokens: Vec<u32>,
    /// Per-position step traces.
    pub steps: Vec<StepTrace>,
    /// `S_0 .. S_n` state chain.
    pub states: Vec<Hash32>,
    /// State preimages (for chain verification).
    pub state_bodies: Vec<TokenStateCommitment>,
    /// Per-step activation trace roots.
    pub trace_roots: Vec<Hash32>,
    /// Final KV cache.
    pub cache: KvCache,
}

impl LaneRun {
    /// Merkle root over all per-step trace roots (the chunk trace root of
    /// the whole run).
    #[must_use]
    pub fn chunk_trace_root(&self) -> Hash32 {
        merkle_root(&self.trace_roots)
    }
}

// The state preimage takes each bound field explicitly by design.
#[allow(clippy::too_many_arguments)]
fn state_commitment(
    job_id: &Hash32,
    model_root: &Hash32,
    profile_id: &Hash32,
    t: u32,
    tokens: &[u32],
    kv: Hash32,
    rng_cursor: u64,
    trace_root: Hash32,
) -> TokenStateCommitment {
    TokenStateCommitment {
        job_id: *job_id,
        model_root: *model_root,
        numeric_profile: *profile_id,
        t,
        token_history_root: token_history_root(tokens),
        kv_commitment: kv,
        rng_cursor,
        trace_root,
    }
}

/// Execute a greedy lane job: prefill the prompt, generate `n_generate`
/// tokens, and commit the `S_t` chain, per-step trace roots, and KV
/// commitments. `tamper` is the cheating-executor hook.
pub fn run_lane(
    model: &MiniModel,
    job_id: Hash32,
    prompt: &[u32],
    n_generate: usize,
    tamper: Option<&Tamper>,
) -> Result<LaneRun, NelError> {
    if prompt.is_empty()
        || n_generate == 0
        || prompt
            .len()
            .checked_add(n_generate)
            .ok_or(NelError::ArithmeticOverflow)?
            > MAX_CONTEXT
    {
        return Err(NelError::InvalidCount);
    }
    let model_root = model.weight_root();
    let profile_id = mini_profile_id();
    let mut cache = KvCache::default();
    let mut tokens = prompt.to_vec();
    let mut steps = Vec::new();
    let mut trace_roots = Vec::new();
    let mut state_bodies = vec![state_commitment(
        &job_id,
        &model_root,
        &profile_id,
        0,
        &tokens,
        cache.commitment(&model_root, &profile_id, &job_id),
        0,
        [0; 32],
    )];
    let mut states = vec![state_bodies[0].commitment()];

    let mut pos = 0u32;
    loop {
        let idx = usize::try_from(pos).map_err(|_| NelError::ArithmeticOverflow)?;
        if idx >= tokens.len() {
            return Err(NelError::WrongPosition);
        }
        let mut step = forward_token(model, &mut cache, pos, tokens[idx], tamper)?;
        let is_last_known = idx == tokens.len().checked_sub(1).ok_or(NelError::InvalidCount)?;
        if is_last_known {
            let next = crate::greedy_token(&step.logits).ok_or(NelError::InvalidCount)?;
            tokens.push(next);
            // Virtual SELECT op payload: the chosen token, committed.
            step.op_payloads[LAYERS][usize::from(ops::SELECT)] = next.to_le_bytes().to_vec();
        }
        // Per-step trace root: activation leaves for every layer output,
        // plus every op commitment as addressable dispute leaves.
        let mut leaves: Vec<Hash32> = step
            .layer_outputs
            .iter()
            .enumerate()
            .map(|(l, bytes)| activation_leaf(&job_id, pos, l as u16, &bytes_of_i8(bytes)))
            .collect();
        for (l, layer_ops) in step.op_payloads.iter().enumerate() {
            for (o, payload) in layer_ops.iter().enumerate() {
                leaves.push(op_commitment(l as u16, o as u16, payload));
            }
        }
        let trace_root = merkle_root(&leaves);
        trace_roots.push(trace_root);
        steps.push(step);
        let t = pos.checked_add(1).ok_or(NelError::ArithmeticOverflow)?;
        let body = state_commitment(
            &job_id,
            &model_root,
            &profile_id,
            t,
            &tokens,
            cache.commitment(&model_root, &profile_id, &job_id),
            0,
            trace_root,
        );
        states.push(body.commitment());
        state_bodies.push(body);
        pos = t;
        if tokens.len()
            == prompt
                .len()
                .checked_add(n_generate)
                .ok_or(NelError::ArithmeticOverflow)?
            && usize::try_from(pos).map_err(|_| NelError::ArithmeticOverflow)?
                == tokens.len().checked_sub(1).ok_or(NelError::InvalidCount)?
        {
            break;
        }
    }
    Ok(LaneRun {
        job_id,
        model_root,
        profile_id,
        prompt_len: prompt.len(),
        tokens,
        steps,
        states,
        state_bodies,
        trace_roots,
        cache,
    })
}

// ---------------------------------------------------------------------------
// Chunk-Freivalds verification and cost law (N-CHUNK-FREIVALDS)
// ---------------------------------------------------------------------------

/// Freivalds verification result with the exact multiplication count the
/// verifier executed (the measured cost surface of the 1/T law).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreivaldsReport {
    /// Whether every challenge vector passed.
    pub accepted: bool,
    /// Multiplications executed.
    pub multiplications: u64,
}

/// Counting twin of [`freivalds_verify_u64`]: identical acceptance relation,
/// plus the exact number of multiplications performed. Kept as a separate
/// implementation so tests can gate dual-verifier agreement.
#[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects)]
pub fn freivalds_verify_u64_counted(
    a: &[u64],
    b: &[u64],
    c: &[u64],
    m: usize,
    k: usize,
    n: usize,
    vectors: &[Vec<u32>],
    profile: FreivaldsProfile,
) -> Result<FreivaldsReport, NelError> {
    if a.len() != m.checked_mul(k).ok_or(NelError::ArithmeticOverflow)?
        || b.len() != k.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?
        || c.len() != m.checked_mul(n).ok_or(NelError::ArithmeticOverflow)?
        || vectors.len() != profile.reps()
        || vectors.iter().any(|r| r.len() != n)
    {
        return Err(NelError::InvalidCount);
    }
    let mut muls = 0u64;
    let mut accepted = true;
    for r in vectors {
        let mut br = vec![0u64; k];
        for (row, slot) in br.iter_mut().enumerate() {
            let mut sum = 0u64;
            for col in 0..n {
                sum = sum.wrapping_add(b[row * n + col].wrapping_mul(u64::from(r[col])));
                muls += 1;
            }
            *slot = sum;
        }
        for row in 0..m {
            let mut left = 0u64;
            let mut right = 0u64;
            for (x, &brx) in br.iter().enumerate() {
                left = left.wrapping_add(a[row * k + x].wrapping_mul(brx));
                muls += 1;
            }
            for col in 0..n {
                right = right.wrapping_add(c[row * n + col].wrapping_mul(u64::from(r[col])));
                muls += 1;
            }
            if left != right {
                accepted = false;
            }
        }
    }
    Ok(FreivaldsReport {
        accepted,
        multiplications: muls,
    })
}

/// Deterministic post-commit challenge vectors:
/// `H(FREIVALDS_CHALLENGE, transcript_root || rep)` expanded to `n` u32s.
#[must_use]
pub fn challenge_vectors(transcript_root: &Hash32, n: usize, reps: usize) -> Vec<Vec<u32>> {
    (0..reps)
        .map(|rep| {
            let mut h = blake3::Hasher::new();
            h.update(domains::FREIVALDS_CHALLENGE.as_bytes());
            h.update(transcript_root);
            h.update(&u32::try_from(rep).unwrap_or(u32::MAX).to_le_bytes());
            let mut bytes = vec![0u8; n.saturating_mul(4)];
            h.finalize_xof().fill(&mut bytes);
            bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        })
        .collect()
}

fn u64s(v: &[i64]) -> Vec<u64> {
    v.iter().map(|&x| x.cast_unsigned()).collect()
}

/// Verify one weight-side op across a whole chunk with a single rectangular
/// Freivalds pass: stacks the T per-token `A` rows and `C32` rows against
/// the shared weight `B`. Returns the measured report.
pub fn verify_chunk_op(
    model: &MiniModel,
    records: &[&MatMulRecord],
    transcript_root: &Hash32,
    profile: FreivaldsProfile,
) -> Result<FreivaldsReport, NelError> {
    let first = records.first().ok_or(NelError::InvalidCount)?;
    let BOperand::Weight(id) = first.b else {
        return Err(NelError::WrongChunkKind);
    };
    let (k, n) = (first.k, first.n);
    let mut a = Vec::new();
    let mut c = Vec::new();
    for r in records {
        if r.layer != first.layer
            || r.op != first.op
            || r.k != k
            || r.n != n
            || r.m != 1
            || r.b != first.b
        {
            return Err(NelError::WrongChunkKind);
        }
        a.extend(u64s(&r.a));
        c.extend(u64s(&r.c));
    }
    let b = u64s(&model.weight_i64(id)?);
    let vectors = challenge_vectors(transcript_root, n, profile.reps());
    freivalds_verify_u64_counted(&a, &b, &c, records.len(), k, n, &vectors, profile)
}

/// Exact multiplication count of one chunk-Freivalds pass at `(t, k, n)`
/// with `reps` challenge vectors: `reps * (k*n + t*k + t*n)` — the
/// `O(KN + TK + TN)` law whose per-token form is `A/T + B`.
#[must_use]
pub fn freivalds_cost_muls(t: u64, k: u64, n: u64, reps: u64) -> u64 {
    reps.saturating_mul(
        k.saturating_mul(n)
            .saturating_add(t.saturating_mul(k))
            .saturating_add(t.saturating_mul(n)),
    )
}

/// Direct recompute multiplication count: `t * k * n`.
#[must_use]
pub fn recompute_cost_muls(t: u64, k: u64, n: u64) -> u64 {
    t.saturating_mul(k).saturating_mul(n)
}

// ---------------------------------------------------------------------------
// Dispute bisection (N-BISECT)
// ---------------------------------------------------------------------------

/// The executor's published commitment grid: state chain, per-layer output
/// commitments, and per-op commitments — the tree the bisection descends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionGrid {
    /// `S_0 .. S_n`.
    pub states: Vec<Hash32>,
    /// `[position][layer]` output commitments (virtual layer last).
    pub layers: Vec<Vec<Hash32>>,
    /// `[position][layer][op]` commitments.
    pub ops: Vec<Vec<Vec<Hash32>>>,
}

/// Build the commitment grid a run publishes: per-op commitments, per-layer
/// roots over each layer's ops, and the `S_t` chain above them.
#[must_use]
pub fn execution_grid(run: &LaneRun) -> ExecutionGrid {
    let ops: Vec<Vec<Vec<Hash32>>> = run
        .steps
        .iter()
        .map(|s| {
            s.op_payloads
                .iter()
                .enumerate()
                .map(|(l, layer_ops)| {
                    layer_ops
                        .iter()
                        .enumerate()
                        .map(|(o, payload)| op_commitment(l as u16, o as u16, payload))
                        .collect()
                })
                .collect()
        })
        .collect();
    let layers = ops
        .iter()
        .map(|step_ops| {
            step_ops
                .iter()
                .map(|layer_ops: &Vec<Hash32>| merkle_root(layer_ops))
                .collect()
        })
        .collect();
    ExecutionGrid {
        states: run.states.clone(),
        layers,
        ops,
    }
}

/// Bisection outcome: the isolated leaf, the number of interactive rounds
/// the descent took, and the referee's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BisectionReport {
    /// Isolated forward position.
    pub position: u32,
    /// Isolated layer (== [`LAYERS`] for the virtual layer).
    pub layer: u16,
    /// Isolated op.
    pub op: u16,
    /// Interactive rounds used by the three descents.
    pub rounds: u32,
    /// Leaf verdict.
    pub verdict: Verdict,
}

/// Interactive-descent boundary: with agreement at `lo0` and disagreement
/// at `hi0`, each probe commits a midpoint and the opponent picks a side;
/// converges to adjacent `(agree, differ)`. One round per probe.
#[allow(clippy::arithmetic_side_effects)]
fn bisect_boundary(
    claimed: &[Hash32],
    reference: &[Hash32],
    lo0: usize,
    hi0: usize,
    rounds: &mut u32,
) -> usize {
    let (mut lo, mut hi) = (lo0, hi0);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        *rounds += 1;
        if claimed[mid] == reference[mid] {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// First index where the two commitment sequences differ.
fn first_divergence(claimed: &[Hash32], reference: &[Hash32]) -> Option<usize> {
    claimed.iter().zip(reference).position(|(a, b)| a != b)
}

/// Run the full dispute: descend token → layer → op against the referee's
/// recomputed grid, then referee the isolated leaf exactly (Freivalds for
/// GEMM accumulators, byte equality for nonlinear payloads, glue equality
/// for inputs). Returns [`Verdict::ChallengerFault`] when the claimed grid
/// matches the reference everywhere.
#[allow(clippy::arithmetic_side_effects)]
pub fn run_bisection(
    model: &MiniModel,
    referee: &LaneRun,
    claimed: &LaneRun,
    profile: FreivaldsProfile,
) -> Result<BisectionReport, NelError> {
    let ref_grid = execution_grid(referee);
    let claim_grid = execution_grid(claimed);
    if ref_grid.states.len() != claim_grid.states.len()
        || claim_grid.states.first() != ref_grid.states.first()
    {
        return Err(NelError::InvalidCount);
    }
    if claim_grid.states == ref_grid.states {
        return Ok(BisectionReport {
            position: 0,
            layer: 0,
            op: 0,
            rounds: 0,
            verdict: Verdict::ChallengerFault,
        });
    }
    let mut rounds = 0u32;
    // Token descent over the S_t chain. The interactive game runs a
    // binary search anchored at the first divergent state (the challenger
    // targets the earliest chunk it can prove wrong); every probe is one
    // forced 200-B move pair.
    let first =
        first_divergence(&claim_grid.states, &ref_grid.states).ok_or(NelError::InvalidCount)?;
    let boundary = bisect_boundary(&claim_grid.states, &ref_grid.states, 0, first, &mut rounds);
    // states[boundary] = S_boundary diverges and S_{boundary-1} agrees, so
    // the diverging execution step is index boundary - 1.
    let position = boundary - 1;
    let step = position;

    // Layer descent inside the disputed step.
    let ref_layers = &ref_grid.layers[step];
    let claim_layers = &claim_grid.layers[step];
    let layer = match first_divergence(claim_layers, ref_layers) {
        // All layer outputs agree but S_{t+1} differs: the divergence is in
        // the chain glue itself (history/KV binding) — executor fault.
        None => {
            return Ok(BisectionReport {
                position: u32::try_from(position).map_err(|_| NelError::ArithmeticOverflow)?,
                layer: 0,
                op: 0,
                rounds,
                verdict: Verdict::ExecutorFault,
            })
        }
        Some(first) => bisect_boundary(claim_layers, ref_layers, 0, first, &mut rounds),
    };

    // Op descent inside the disputed layer.
    let ref_ops = &ref_grid.ops[step][layer];
    let claim_ops = &claim_grid.ops[step][layer];
    let op = match first_divergence(claim_ops, ref_ops) {
        // Layer commitment differs but every op payload matches: the layer
        // output commitment itself is inconsistent with its own ops.
        None => {
            return Ok(BisectionReport {
                position: u32::try_from(position).map_err(|_| NelError::ArithmeticOverflow)?,
                layer: u16::try_from(layer).map_err(|_| NelError::ArithmeticOverflow)?,
                op: 0,
                rounds,
                verdict: Verdict::ExecutorFault,
            })
        }
        Some(first) => bisect_boundary(claim_ops, ref_ops, 0, first, &mut rounds),
    };
    let layer16 = u16::try_from(layer).map_err(|_| NelError::ArithmeticOverflow)?;
    let op16 = u16::try_from(op).map_err(|_| NelError::ArithmeticOverflow)?;

    let verdict = referee_leaf(model, referee, claimed, step, layer16, op16, profile)?;
    Ok(BisectionReport {
        position: u32::try_from(position).map_err(|_| NelError::ArithmeticOverflow)?,
        layer: layer16,
        op: op16,
        rounds,
        verdict,
    })
}

/// The exact leaf referee for one isolated `(position, layer, op)`:
/// - GEMM ops: input glue equality against the agreed prefix, then a
///   Freivalds check of the claimed C32 against the committed operands.
/// - Nonlinear ops: exact recompute (the referee's own payload) equality.
fn referee_leaf(
    model: &MiniModel,
    referee: &LaneRun,
    claimed: &LaneRun,
    step: usize,
    layer: u16,
    op: u16,
    profile: FreivaldsProfile,
) -> Result<Verdict, NelError> {
    let is_gemm = (usize::from(layer) < LAYERS
        && matches!(
            op,
            ops::QKV | ops::SCORES | ops::PV | ops::OUT | ops::GATE | ops::UP | ops::DOWN
        ))
        || (usize::from(layer) == LAYERS && op == ops::LM_HEAD);
    if is_gemm {
        let select = |run: &LaneRun| -> Vec<MatMulRecord> {
            run.steps[step]
                .matmuls
                .iter()
                .filter(|r| r.layer == layer && r.op == op)
                .cloned()
                .collect()
        };
        let claimed_records = select(claimed);
        let referee_records = select(referee);
        if claimed_records.len() != referee_records.len() {
            return Ok(Verdict::ExecutorFault);
        }
        let transcript_root = claimed.chunk_trace_root();
        for (cr, rr) in claimed_records.iter().zip(&referee_records) {
            // Glue: the leaf's inputs are the agreed prefix. A claimed input
            // differing from the committed prefix is an immediate fault.
            if cr.a != rr.a || cr.b != rr.b || cr.m != rr.m || cr.k != rr.k || cr.n != rr.n {
                return Ok(Verdict::ExecutorFault);
            }
            let b = match &cr.b {
                BOperand::Weight(id) => model.weight_i64(*id)?,
                BOperand::Inline(inline) => inline.clone(),
            };
            let vectors = challenge_vectors(&transcript_root, cr.n, profile.reps());
            let ok = freivalds_verify_u64(
                &u64s(&cr.a),
                &u64s(&b),
                &u64s(&cr.c),
                cr.m,
                cr.k,
                cr.n,
                &vectors,
                profile,
            )?;
            if !ok {
                return Ok(Verdict::ExecutorFault);
            }
        }
        // Accumulators verified; the payload must be their pinned requant,
        // i.e. byte-equal to the referee's own payload.
        if claimed.steps[step].op_payloads[usize::from(layer)][usize::from(op)]
            != referee.steps[step].op_payloads[usize::from(layer)][usize::from(op)]
        {
            return Ok(Verdict::ExecutorFault);
        }
        Ok(Verdict::ChallengerFault)
    } else {
        // Nonlinear / structural op: exact integer recompute.
        if claimed.steps[step].op_payloads[usize::from(layer)][usize::from(op)]
            != referee.steps[step].op_payloads[usize::from(layer)][usize::from(op)]
        {
            Ok(Verdict::ExecutorFault)
        } else {
            Ok(Verdict::ChallengerFault)
        }
    }
}

// ---------------------------------------------------------------------------
// Integer sampler (N-SAMPLER)
// ---------------------------------------------------------------------------

/// Derive one uniform variate:
/// `H(DRAW, beacon || job_id || token_index || round || draw_index)`.
#[must_use]
pub fn draw_hash(
    beacon: &Hash32,
    job_id: &Hash32,
    token_index: u32,
    round: u64,
    draw_index: u64,
) -> Hash32 {
    let mut body = Vec::with_capacity(84);
    body.extend(beacon);
    body.extend(job_id);
    body.extend(token_index.to_le_bytes());
    body.extend(round.to_le_bytes());
    body.extend(draw_index.to_le_bytes());
    domain_hash(domains::DRAW, &body)
}

/// Sampler parameters: top-k truncation and Q1.15 top-p threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplerParams {
    /// Keep at most this many tokens (>= 1).
    pub top_k: u32,
    /// Shortest prefix with cumulative mass >= this Q1.15 value.
    pub top_p_q15: u32,
}

/// The pinned integer stochastic sampler (§7.3): integer softmax masses,
/// total order `(mass desc, token_id asc)`, top-k then top-p (boundary
/// included), one beacon-derived draw, `target = u mod S`, first token with
/// cumulative mass > target. Returns `(token_id, next_rng_cursor)`.
#[allow(clippy::arithmetic_side_effects)]
pub fn sample_token(
    logits: &[i32],
    params: SamplerParams,
    beacon: &Hash32,
    job_id: &Hash32,
    token_index: u32,
    round: u64,
    rng_cursor: u64,
) -> Result<(u32, u64), NelError> {
    if logits.is_empty() || params.top_k == 0 {
        return Err(NelError::InvalidCount);
    }
    let masses = softmax_q15(logits, logits.len())?;
    let mut order: Vec<(u32, u64)> = masses
        .iter()
        .enumerate()
        .map(|(i, &m)| {
            Ok((
                u32::try_from(i).map_err(|_| NelError::ArithmeticOverflow)?,
                u64::try_from(i16::max(m, 0)).unwrap_or(0),
            ))
        })
        .collect::<Result<_, NelError>>()?;
    // Pinned total order: mass descending, token id ascending.
    order.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    let k = usize::try_from(params.top_k).map_err(|_| NelError::ArithmeticOverflow)?;
    order.truncate(k.max(1));
    // Top-p: shortest prefix with cumulative mass >= threshold (boundary
    // included); the whole kept set when the threshold exceeds its mass.
    let mut cut = order.len();
    let mut cum = 0u64;
    for (i, &(_, m)) in order.iter().enumerate() {
        cum += m;
        if cum >= u64::from(params.top_p_q15) {
            cut = i + 1;
            break;
        }
    }
    order.truncate(cut.max(1));
    let total: u64 = order.iter().map(|&(_, m)| m).sum();
    if total == 0 {
        return Err(NelError::ArithmeticOverflow);
    }
    let u = draw_hash(beacon, job_id, token_index, round, rng_cursor);
    // Pinned reduction: 256-bit big-endian Horner fold mod S.
    let mut target = 0u64;
    for &byte in &u {
        target = (target * 256 + u64::from(byte)) % total;
    }
    let mut acc = 0u64;
    for &(id, m) in &order {
        acc += m;
        if acc > target {
            return Ok((
                id,
                rng_cursor
                    .checked_add(1)
                    .ok_or(NelError::ArithmeticOverflow)?,
            ));
        }
    }
    Err(NelError::InvalidCount)
}

#[cfg(test)]
mod tests;
