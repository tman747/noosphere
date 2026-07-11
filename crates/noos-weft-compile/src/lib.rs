//! Deterministic proof-carrying Weft-to-Grain elaboration.
#![forbid(unsafe_code)]

use noos_grain::{encode_noun, Noun};
use noos_weft_syntax::{
    canonical_program, check, BinOp, Diagnostic, Effect, Expr, ExprKind, Function, Program, Size,
    Type,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const COMPILER_NAME: &str = "noos-weftc";
pub const COMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GRAIN_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CostDerivation {
    pub declared: String,
    pub derived_constant: u64,
    pub branch_law: String,
    pub call_charge: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SizeBound {
    pub variable: String,
    pub maximum: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoweringManifest {
    pub target: String,
    pub hash: String,
    pub transcript_layout: Option<String>,
    pub journal_schema: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeaningContract {
    pub formula_id: String,
    pub grain_version: u32,
    pub compiler_id: String,
    pub source_root: String,
    pub type_signature: String,
    pub numeric_profiles: Vec<String>,
    pub cost_certificate: String,
    pub effects: Vec<String>,
    pub rights: Vec<String>,
    pub size_bounds: Vec<SizeBound>,
    pub lowerings: Vec<LoweringManifest>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeftUnit {
    pub name: String,
    pub grain_formula_hex: String,
    pub formula_id: String,
    pub meaning_contract: MeaningContract,
    pub cost: CostDerivation,
    pub obligations: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compilation {
    pub schema: String,
    pub source_root: String,
    pub compiler_id: String,
    pub units: Vec<WeftUnit>,
}

fn hash(domain: &str, bytes: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    h.update(bytes);
    h.finalize().to_hex().to_string()
}
fn atom(v: u64) -> Noun {
    Noun::atom_u64(v)
}
fn cell(a: Noun, b: Noun) -> Result<Noun, Diagnostic> {
    Noun::cell(a, b).map_err(|_| Diagnostic {
        code: "E-LOWER-001",
        span: Default::default(),
        message: "formula exceeds Grain noun depth".into(),
    })
}
fn op(code: u64, arg: Noun) -> Result<Noun, Diagnostic> {
    cell(atom(code), arg)
}
fn pair(a: Noun, b: Noun) -> Result<Noun, Diagnostic> {
    cell(a, b)
}
fn quote(n: Noun) -> Result<Noun, Diagnostic> {
    op(1, n)
}
fn slot(axis: u64) -> Result<Noun, Diagnostic> {
    op(0, atom(axis))
}
fn op2(code: u64, a: Noun, b: Noun) -> Result<Noun, Diagnostic> {
    op(code, pair(a, b)?)
}
fn op3(code: u64, a: Noun, b: Noun, c: Noun) -> Result<Noun, Diagnostic> {
    op(code, pair(a, pair(b, c)?)?)
}
fn list_data(xs: &[Noun]) -> Result<Noun, Diagnostic> {
    let mut n = atom(0);
    for x in xs.iter().rev() {
        n = pair(x.clone(), n)?
    }
    Ok(n)
}
fn param_axis(index: usize) -> Result<u64, Diagnostic> {
    let shift = u32::try_from(index.saturating_add(3)).map_err(|_| Diagnostic {
        code: "E-LOWER-002",
        span: Default::default(),
        message: "too many parameters".into(),
    })?;
    1u64.checked_shl(shift)
        .and_then(|v| v.checked_sub(2))
        .ok_or(Diagnostic {
            code: "E-LOWER-002",
            span: Default::default(),
            message: "too many parameters".into(),
        })
}
fn arm_axis(index: usize) -> Result<u64, Diagnostic> {
    let shift = u32::try_from(index.saturating_add(1)).map_err(|_| Diagnostic {
        code: "E-LOWER-002",
        span: Default::default(),
        message: "too many functions".into(),
    })?;
    3u64.checked_shl(shift)
        .and_then(|v| v.checked_sub(2))
        .ok_or(Diagnostic {
            code: "E-LOWER-002",
            span: Default::default(),
            message: "too many functions".into(),
        })
}

/// Grain-v1 charge constants mirrored from `noos-grain` (frozen spec §10).
/// The lowering computes an exact-shape static upper bound alongside every
/// emitted formula, so drift between emission and certificate is impossible.
const G_CONS: u64 = 4;
const G_ALLOC: u64 = 3;
const G_QUOTE: u64 = 1;
const G_IF: u64 = 3;
const G_PUSH: u64 = 3;
const G_ARM: u64 = 4;
const G_INC_BASE: u64 = 2;
const G_EQ_BASE: u64 = 2;

/// Worst-case size of a runtime value, for size-dependent charges
/// (`inc` word cost, `equal` node/word walk).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValBound {
    /// 8-byte words across every atom in the value.
    pub words: u64,
    /// Noun nodes (atoms + cells) in the value.
    pub nodes: u64,
}

impl ValBound {
    const SCALAR: ValBound = ValBound { words: 2, nodes: 1 };
    const UNIT: ValBound = ValBound { words: 0, nodes: 1 };
    fn join(self, other: ValBound) -> ValBound {
        ValBound {
            words: self.words.max(other.words),
            nodes: self.nodes.max(other.nodes),
        }
    }
}

/// Worst-case value size for a declared Weft type: u64 scalars stay within
/// two words even after the maximum literal-addition unroll (u64::MAX +
/// 4096 fits nine bytes); tuples are right-nested lists with a zero
/// terminator.
fn type_bound(t: &Type) -> ValBound {
    match t {
        Type::Tuple(ts) => {
            let mut words = 0u64;
            let mut nodes = 1u64; // zero-atom terminator
            for t in ts {
                let b = type_bound(t);
                words = words.saturating_add(b.words);
                // One list cell per element plus the element itself.
                nodes = nodes.saturating_add(1).saturating_add(b.nodes);
            }
            ValBound { words, nodes }
        }
        Type::Linear(t) | Type::Committed(t, _) | Type::Rights(t, _) | Type::Dream(t) => {
            type_bound(t)
        }
        _ => ValBound::SCALAR,
    }
}

/// Static charge bound for `slot` on `axis` (spec §7).
fn slot_bound(axis: u64) -> u64 {
    let bits = 64u64.saturating_sub(u64::from(axis.leading_zeros()));
    2u64.saturating_add(bits.saturating_sub(1))
}

/// A lowered formula plus its static grain charge bound and the size bound
/// of the value it produces.
struct Lowered {
    formula: Noun,
    steps: u64,
    val: ValBound,
}

struct Lower<'a> {
    params: BTreeMap<String, (u64, ValBound)>,
    arms: &'a BTreeMap<String, u64>,
    /// Per-callee `(body steps, body value)` bound; `None` while the callee
    /// participates in a recursive cycle (no static constant exists).
    fn_bounds: &'a BTreeMap<String, Option<(u64, ValBound)>>,
}

impl Lower<'_> {
    fn expr(&self, e: &Expr) -> Result<Lowered, Diagnostic> {
        Ok(match &e.kind {
            ExprKind::Var(n) => {
                let (axis, val) = *self.params.get(n).ok_or_else(|| Diagnostic {
                    code: "E-LOWER-004",
                    span: e.span,
                    message: format!("local '{n}' escaped normalization"),
                })?;
                Lowered {
                    formula: slot(axis)?,
                    steps: slot_bound(axis),
                    val,
                }
            }
            ExprKind::Int(n) => Lowered {
                formula: quote(atom(*n))?,
                steps: G_QUOTE,
                val: ValBound::SCALAR,
            },
            // Loobean booleans (spec §9 op 5/6): TRUE is atom 0, FALSE is
            // atom 1, matching `equal`'s result and `if`'s dispatch law.
            ExprKind::Bool(v) => Lowered {
                formula: quote(atom(u64::from(!*v)))?,
                steps: G_QUOTE,
                val: ValBound::SCALAR,
            },
            ExprKind::Tuple(xs) => {
                let parts = xs
                    .iter()
                    .map(|x| self.expr(x))
                    .collect::<Result<Vec<_>, _>>()?;
                self.cons_list(parts)?
            }
            ExprKind::Let(n, v, b) => {
                let value = self.expr(v)?;
                let mut nested = Lower {
                    params: self.params.clone(),
                    arms: self.arms,
                    fn_bounds: self.fn_bounds,
                };
                for (axis, _) in nested.params.values_mut() {
                    *axis =
                        axis.checked_mul(2)
                            .and_then(|x| x.checked_add(2))
                            .ok_or(Diagnostic {
                                code: "E-LOWER-002",
                                span: e.span,
                                message: "local axis overflow".into(),
                            })?
                }
                nested.params.insert(n.clone(), (2, value.val));
                let body = nested.expr(b)?;
                Lowered {
                    formula: op2(8, value.formula, body.formula)?,
                    steps: G_PUSH
                        .saturating_add(value.steps)
                        .saturating_add(G_ALLOC)
                        .saturating_add(body.steps),
                    val: body.val,
                }
            }
            ExprKind::If(c, a, b) => {
                let cond = self.expr(c)?;
                let then = self.expr(a)?;
                let els = self.expr(b)?;
                Lowered {
                    formula: op3(6, cond.formula, then.formula, els.formula)?,
                    steps: G_IF
                        .saturating_add(cond.steps)
                        .saturating_add(then.steps.max(els.steps)),
                    val: then.val.join(els.val),
                }
            }
            ExprKind::Binary(BinOp::Eq, a, b) => {
                let x = self.expr(a)?;
                let y = self.expr(b)?;
                // metered_eq visits at most min(nodes) node pairs and
                // min(words) atom words when both sides share one type.
                let walk = x.val.nodes.min(y.val.nodes);
                let words = x.val.words.min(y.val.words);
                Lowered {
                    formula: op2(5, x.formula, y.formula)?,
                    steps: G_EQ_BASE
                        .saturating_add(x.steps)
                        .saturating_add(y.steps)
                        .saturating_add(walk)
                        .saturating_add(words),
                    val: ValBound::SCALAR,
                }
            }
            ExprKind::Binary(BinOp::Add, a, b) => {
                if let ExprKind::Int(n) = b.kind {
                    if n > 4096 {
                        return Err(Diagnostic {
                            code: "E-LOWER-003",
                            span: e.span,
                            message: "literal addition unroll exceeds 4096".into(),
                        });
                    }
                    let x = self.expr(a)?;
                    let mut formula = x.formula;
                    for _ in 0..n {
                        formula = op(4, formula)?
                    }
                    // Per inc: completion charge (base + operand words)
                    // plus the result-atom allocation (1 + result words).
                    let per_inc = G_INC_BASE
                        .saturating_add(x.val.words.max(2))
                        .saturating_add(1)
                        .saturating_add(x.val.words.max(2));
                    Lowered {
                        formula,
                        steps: x.steps.saturating_add(n.saturating_mul(per_inc)),
                        val: ValBound::SCALAR,
                    }
                } else if let (ExprKind::Int(x), ExprKind::Int(y)) = (&a.kind, &b.kind) {
                    Lowered {
                        formula: quote(atom(x.checked_add(*y).ok_or(Diagnostic {
                            code: "E-LOWER-003",
                            span: e.span,
                            message: "constant arithmetic overflow".into(),
                        })?))?,
                        steps: G_QUOTE,
                        val: ValBound::SCALAR,
                    }
                } else {
                    return Err(Diagnostic {
                        code: "E-LOWER-003",
                        span: e.span,
                        message: "v1 lowering requires a literal right operand for addition".into(),
                    });
                }
            }
            ExprKind::Binary(BinOp::Mul, a, b) => {
                if let (ExprKind::Int(x), ExprKind::Int(y)) = (&a.kind, &b.kind) {
                    Lowered {
                        formula: quote(atom(x.checked_mul(*y).ok_or(Diagnostic {
                            code: "E-LOWER-003",
                            span: e.span,
                            message: "constant arithmetic overflow".into(),
                        })?))?,
                        steps: G_QUOTE,
                        val: ValBound::SCALAR,
                    }
                } else {
                    return Err(Diagnostic {
                        code: "E-LOWER-003",
                        span: e.span,
                        message: "v1 lowering accepts multiplication only when constant-foldable"
                            .into(),
                    });
                }
            }
            ExprKind::Binary(_, _, _) => {
                return Err(Diagnostic {
                    code: "E-LOWER-003",
                    span: e.span,
                    message: "operator has no exact Grain v1 lowering".into(),
                })
            }
            ExprKind::Consume(x) => {
                let _ = self.expr(x)?;
                Lowered {
                    formula: quote(atom(0))?,
                    steps: G_QUOTE,
                    val: ValBound::UNIT,
                }
            }
            ExprKind::Call(n, args) if matches!(n.as_str(), "commit" | "beacon" | "declassify") => {
                let parts = args
                    .iter()
                    .map(|x| self.expr(x))
                    .collect::<Result<Vec<_>, _>>()?;
                let data = self.cons_list(parts)?;
                Lowered {
                    // [11 hint f]: the hint head is pure data (never
                    // evaluated, COST_HINT = 0); only `data` runs.
                    formula: op2(
                        11,
                        quote(atom(match n.as_str() {
                            "commit" => 1,
                            "beacon" => 2,
                            _ => 3,
                        }))?,
                        data.formula,
                    )?,
                    steps: data.steps,
                    val: data.val,
                }
            }
            ExprKind::Call(n, args) => {
                let axis = *self.arms.get(n).ok_or_else(|| Diagnostic {
                    code: "E-LOWER-005",
                    span: e.span,
                    message: "unknown arm".into(),
                })?;
                let parts = args
                    .iter()
                    .map(|x| self.expr(x))
                    .collect::<Result<Vec<_>, _>>()?;
                let arg_list = self.cons_list(parts)?;
                let new_core = pair(slot(6)?, slot(2)?)?;
                let arm = op(9, pair(atom(axis), new_core)?)?;
                let callee = self.fn_bounds.get(n).copied().flatten();
                // new_core cons composition: CONS + slot(6) + slot(2) + cell.
                let core_steps = G_CONS
                    .saturating_add(slot_bound(6))
                    .saturating_add(slot_bound(2))
                    .saturating_add(G_ALLOC);
                let (body_steps, body_val) = callee.unwrap_or((u64::MAX, ValBound::SCALAR));
                Lowered {
                    formula: op2(8, arg_list.formula, arm)?,
                    steps: G_PUSH
                        .saturating_add(arg_list.steps)
                        .saturating_add(G_ALLOC)
                        .saturating_add(G_ARM)
                        .saturating_add(core_steps)
                        .saturating_add(slot_bound(axis))
                        .saturating_add(body_steps),
                    val: body_val,
                }
            }
            ExprKind::Field(_, _) => {
                return Err(Diagnostic {
                    code: "E-LOWER-006",
                    span: e.span,
                    message: "record projection is not in the core release".into(),
                })
            }
        })
    }

    /// Right-nested runtime list: one cons-composition cell per element
    /// plus the quoted zero terminator.
    fn cons_list(&self, parts: Vec<Lowered>) -> Result<Lowered, Diagnostic> {
        let mut formula = quote(atom(0))?;
        let mut steps = G_QUOTE;
        let mut words = 0u64;
        let mut nodes = 1u64;
        for part in parts.iter().rev() {
            formula = pair(part.formula.clone(), formula)?;
            steps = steps
                .saturating_add(G_CONS)
                .saturating_add(part.steps)
                .saturating_add(G_ALLOC);
        }
        for part in &parts {
            words = words.saturating_add(part.val.words);
            nodes = nodes.saturating_add(1).saturating_add(part.val.nodes);
        }
        Ok(Lowered {
            formula,
            steps,
            val: ValBound { words, nodes },
        })
    }
}
fn signature(f: &Function) -> String {
    format!(
        "fn({})->{} !{{{}}}",
        f.params
            .iter()
            .map(|p| p.ty.canonical())
            .collect::<Vec<_>>()
            .join(","),
        f.ret.canonical(),
        f.effects
            .iter()
            .map(Effect::canonical)
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn profiles_type(t: &Type, out: &mut BTreeSet<String>) {
    match t {
        Type::Tensor(t, _, p) => {
            out.insert(p.clone());
            profiles_type(t, out)
        }
        Type::Tuple(ts) => {
            for t in ts {
                profiles_type(t, out)
            }
        }
        Type::Vec(t, _)
        | Type::Linear(t)
        | Type::Rights(t, _)
        | Type::Committed(t, _)
        | Type::Dream(t) => profiles_type(t, out),
        _ => {}
    }
}
fn rights_type(t: &Type, out: &mut BTreeSet<String>) {
    match t {
        Type::Rights(t, r) => {
            out.extend(r.clone());
            rights_type(t, out)
        }
        Type::Tuple(ts) => {
            for t in ts {
                rights_type(t, out)
            }
        }
        Type::Vec(t, _)
        | Type::Linear(t)
        | Type::Committed(t, _)
        | Type::Dream(t)
        | Type::Tensor(t, _, _) => rights_type(t, out),
        _ => {}
    }
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char)
    }
    s
}

pub fn compile(source: &str) -> Result<Compilation, Vec<Diagnostic>> {
    let p = noos_weft_syntax::parse(source)?;
    compile_program(&p)
}
pub fn compile_program(p: &Program) -> Result<Compilation, Vec<Diagnostic>> {
    let checked = check(p)?;
    let source_bytes = canonical_program(p);
    let source_root = hash("NOOS/WEFT/SOURCE/V1", &source_bytes);
    let compiler_id = hash(
        "NOOS/WEFT/COMPILER/V1",
        format!("{COMPILER_NAME}/{COMPILER_VERSION};grain=1;rust-edition=2021").as_bytes(),
    );
    let mut arms = BTreeMap::new();
    for (i, f) in checked.iter().enumerate() {
        match arm_axis(i) {
            Ok(a) => {
                arms.insert(f.function.name.clone(), a);
            }
            Err(e) => return Err(vec![e]),
        }
    }
    // Static per-function bounds by fixpoint: start every callee unknown
    // (recursive cycles stay unknown forever — no static constant exists),
    // then re-lower until the known set stops growing. Calls use arm axes
    // only, so formula emission itself never needs a callee body.
    let mut fn_bounds: BTreeMap<String, Option<(u64, ValBound)>> = checked
        .iter()
        .map(|f| (f.function.name.clone(), None))
        .collect();
    let lower_for = |f: &noos_weft_syntax::CheckedFunction,
                     fn_bounds: &BTreeMap<String, Option<(u64, ValBound)>>|
     -> Result<Lowered, Vec<Diagnostic>> {
        let params = f
            .function
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| param_axis(i).map(|a| (p.name.clone(), (a, type_bound(&p.ty)))))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(|e| vec![e])?;
        let l = Lower {
            params,
            arms: &arms,
            fn_bounds,
        };
        l.expr(&f.function.body).map_err(|e| vec![e])
    };
    loop {
        let mut grew = false;
        for f in &checked {
            if fn_bounds.get(&f.function.name).copied().flatten().is_some() {
                continue;
            }
            let lowered = lower_for(f, &fn_bounds)?;
            if lowered.steps != u64::MAX {
                fn_bounds.insert(f.function.name.clone(), Some((lowered.steps, lowered.val)));
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    let mut bodies = Vec::new();
    let mut body_bounds = Vec::new();
    for f in &checked {
        let lowered = lower_for(f, &fn_bounds)?;
        bodies.push(lowered.formula);
        body_bounds.push(lowered.steps);
    }
    let battery = list_data(&bodies).map_err(|e| vec![e])?;
    let mut units = Vec::new();
    for (idx, f) in checked.iter().enumerate() {
        let core_formula = pair(
            quote(battery.clone()).map_err(|e| vec![e])?,
            slot(1).map_err(|e| vec![e])?,
        )
        .and_then(|core| op(9, pair(atom(arm_axis(idx)?), core)?))
        .map_err(|e| vec![e])?;
        let bytes = encode_noun(&core_formula);
        let formula_id = hash("NOOS/WEFT/FORMULA/V1", &bytes);
        let mut ps = BTreeSet::new();
        let mut rs = BTreeSet::new();
        for p in &f.function.params {
            profiles_type(&p.ty, &mut ps);
            rights_type(&p.ty, &mut rs)
        }
        profiles_type(&f.function.ret, &mut ps);
        rights_type(&f.function.ret, &mut rs);
        let declared = f
            .function
            .cost
            .as_ref()
            .map(Size::canonical)
            .unwrap_or_else(|| f.inferred_cost.to_string());
        // Unit wrapper: cons-composed core `[quote(battery) slot(1)]`
        // (CONS + QUOTE + slot(1) + cell alloc) plus the arm dispatch.
        let wrapper = G_CONS
            .saturating_add(G_QUOTE)
            .saturating_add(slot_bound(1))
            .saturating_add(G_ALLOC)
            .saturating_add(G_ARM)
            .saturating_add(slot_bound(arms.get(&f.function.name).copied().unwrap_or(2)));
        let derived_constant = match body_bounds[idx] {
            u64::MAX => 0, // recursive: no static constant; declared cost governs
            steps => wrapper.saturating_add(steps),
        };
        let cost = CostDerivation {
            declared,
            derived_constant,
            branch_law: "grain-v1 static bound; if=max(then,else); recursion=0 (declared governs)"
                .into(),
            call_charge: 8,
        };
        let cost_bytes = serde_json::to_vec(&cost).map_err(|_| {
            vec![Diagnostic {
                code: "E-EMIT-001",
                span: f.function.span,
                message: "cost serialization failed".into(),
            }]
        })?;
        let cost_certificate = hash("NOOS/WEFT/COST/V1", &cost_bytes);
        let lowerings = vec![LoweringManifest {
            target: "grain-v1".into(),
            hash: formula_id.clone(),
            transcript_layout: None,
            journal_schema: None,
        }];
        let mc = MeaningContract {
            formula_id: formula_id.clone(),
            grain_version: GRAIN_VERSION,
            compiler_id: compiler_id.clone(),
            source_root: source_root.clone(),
            type_signature: signature(&f.function),
            numeric_profiles: ps.into_iter().collect(),
            cost_certificate,
            effects: f.inferred_effects.iter().map(Effect::canonical).collect(),
            rights: rs.into_iter().collect(),
            size_bounds: f
                .function
                .sizes
                .iter()
                .map(|v| SizeBound {
                    variable: v.clone(),
                    maximum: 65535,
                })
                .collect(),
            lowerings,
        };
        units.push(WeftUnit {
            name: f.function.name.clone(),
            grain_formula_hex: hex(&bytes),
            formula_id,
            meaning_contract: mc,
            cost,
            obligations: Vec::new(),
        })
    }
    Ok(Compilation {
        schema: "WeftCompilation/v1".into(),
        source_root,
        compiler_id,
        units,
    })
}

/// Frozen W8A8v1 reference arithmetic: exact i32 accumulation.
// Dims are validated <= 65535, so index arithmetic is in-bounds and every
// i8 x i8 product plus u16-bounded accumulation fits i64 exactly.
#[allow(clippy::arithmetic_side_effects)]
pub fn gemm_i8(
    a: &[i8],
    b: &[i8],
    m: usize,
    k: usize,
    n: usize,
) -> Result<Vec<i32>, CertificateError> {
    if a.len() != m.checked_mul(k).ok_or(CertificateError::Shape)?
        || b.len() != k.checked_mul(n).ok_or(CertificateError::Shape)?
        || m == 0
        || k == 0
        || n == 0
        || m > 65535
        || k > 65535
        || n > 65535
    {
        return Err(CertificateError::Shape);
    }
    let mut c = vec![0i32; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut acc = 0i64;
            for q in 0..k {
                acc = acc
                    .checked_add(i64::from(a[i * k + q]) * i64::from(b[q * n + j]))
                    .ok_or(CertificateError::AccumOverflow)?
            }
            c[i * n + j] = i32::try_from(acc).map_err(|_| CertificateError::AccumOverflow)?
        }
    }
    Ok(c)
}
// `shift` is validated in 1..=31, so `shift - 1`, the i32 x u32 product, and
// the rounding add are all exactly representable in i64.
#[allow(clippy::arithmetic_side_effects)]
pub fn requant_w8a8(c: &[i32], mult: u32, shift: u8) -> Result<Vec<i8>, CertificateError> {
    if mult == 0 || shift == 0 || shift > 31 {
        return Err(CertificateError::Profile);
    }
    let round = 1i64 << (shift - 1);
    c.iter()
        .map(|x| {
            let q = (i64::from(*x) * i64::from(mult) + round) >> shift;
            Ok(q.clamp(-128, 127) as i8)
        })
        .collect()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpanCertificate {
    pub m: u16,
    pub k: u16,
    pub n: u16,
    pub reps: u8,
    pub rbits: u8,
    pub commitment: String,
    pub challenge: [u32; 2],
    pub projections: Vec<u64>,
    pub c32_hash: String,
    pub c8_hash: String,
    pub mult: u32,
    pub shift: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateError {
    Shape,
    Profile,
    AccumOverflow,
    Soundness,
    Commitment,
    Projection,
    Output,
    /// The Freivalds span relation `C·w == A·(B·w)` failed: the claimed
    /// product is not `A×B`, even though every transcript binding matched.
    Relation,
}
fn ints_bytes(v: &[i32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}
fn i8_bytes(v: &[i8]) -> Vec<u8> {
    v.iter().map(|x| x.to_le_bytes()[0]).collect()
}
/// Frozen span transcript commitment: `H(A || B || C32 || C8 || m || k ||
/// n || mult || shift)` under the W8A8 commit domain. Public so falsifier
/// harnesses can forge internally consistent transcripts over a wrong
/// product and prove exactly where each admission path rejects them.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn commit_span_transcript(
    a: &[i8],
    b: &[i8],
    c: &[i32],
    c8: &[i8],
    m: u16,
    k: u16,
    n: u16,
    mult: u32,
    shift: u8,
) -> String {
    let mut transcript = Vec::new();
    transcript.extend(i8_bytes(a));
    transcript.extend(i8_bytes(b));
    transcript.extend(ints_bytes(c));
    transcript.extend(i8_bytes(c8));
    transcript.extend(m.to_le_bytes());
    transcript.extend(k.to_le_bytes());
    transcript.extend(n.to_le_bytes());
    transcript.extend(mult.to_le_bytes());
    transcript.push(shift);
    hash("NOOS/WEFT/W8A8/COMMIT/V1", &transcript)
}

/// Flat rotated-challenge projections over a claimed `C32` (the frozen
/// transcript layout: the weight of flat element `i` is `rot_l(r, i mod
/// 32)`; arithmetic is wrapping u64 by law).
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // i % 32 < 32; wrapping is the frozen law
pub fn project_span(c: &[i32], challenge: [u32; 2]) -> Vec<u64> {
    let mut projections = Vec::with_capacity(challenge.len());
    for r in challenge {
        let mut total = 0u64;
        for (i, x) in c.iter().enumerate() {
            let rot = r.rotate_left((i % 32) as u32);
            total = total.wrapping_add((*x as i64 as u64).wrapping_mul(u64::from(rot)));
        }
        projections.push(total);
    }
    projections
}

#[allow(clippy::too_many_arguments)]
pub fn derive_span_certificate(
    a: &[i8],
    b: &[i8],
    m: u16,
    k: u16,
    n: u16,
    mult: u32,
    shift: u8,
    challenge: [u32; 2],
) -> Result<SpanCertificate, CertificateError> {
    let c = gemm_i8(a, b, m.into(), k.into(), n.into())?;
    let c8 = requant_w8a8(&c, mult, shift)?;
    Ok(SpanCertificate {
        m,
        k,
        n,
        reps: 2,
        rbits: 32,
        commitment: commit_span_transcript(a, b, &c, &c8, m, k, n, mult, shift),
        challenge,
        projections: project_span(&c, challenge),
        c32_hash: hash("NOOS/WEFT/W8A8/C32/V1", &ints_bytes(&c)),
        c8_hash: hash("NOOS/WEFT/W8A8/C8/V1", &i8_bytes(&c8)),
        mult,
        shift,
    })
}
pub fn admit_span_certificate(
    cert: &SpanCertificate,
    a: &[i8],
    b: &[i8],
    claimed_c: &[i32],
    claimed_c8: &[i8],
) -> Result<(), CertificateError> {
    if cert.reps != 2 || cert.rbits != 32 {
        return Err(CertificateError::Soundness);
    }
    let fresh = derive_span_certificate(
        a,
        b,
        cert.m,
        cert.k,
        cert.n,
        cert.mult,
        cert.shift,
        cert.challenge,
    )?;
    if fresh.commitment != cert.commitment {
        return Err(CertificateError::Commitment);
    }
    if fresh.projections != cert.projections {
        return Err(CertificateError::Projection);
    }
    if fresh.c32_hash != hash("NOOS/WEFT/W8A8/C32/V1", &ints_bytes(claimed_c))
        || fresh.c8_hash != hash("NOOS/WEFT/W8A8/C8/V1", &i8_bytes(claimed_c8))
    {
        return Err(CertificateError::Output);
    }
    Ok(())
}

/// Exact integer Freivalds span relation in `O(reps * (kn + mn + mk))`:
/// for every challenge word `r`, with per-column weights `w_j = rot_l(r, j
/// mod 32)`, checks `C·w == A·(B·w)`. The identity holds for every `w`
/// exactly when `C == A×B` over the integers; a wrong product survives one
/// rep only with probability ~`2^-rbits` over a random `r`. Returns the
/// exact multiply-accumulate count — the deterministic cycle-envelope
/// proxy, quadratic in the side at square shapes (the derivation itself is
/// cubic).
///
/// Magnitude bounds justify unchecked i128 arithmetic: `|a|,|b| <= 128`,
/// `|c| < 2^31`, `w < 2^32`, dims `<= 65535`, so `|B·w| < 2^55`,
/// `|A·(B·w)| < 2^79`, `|C·w| < 2^80` — all far inside i128.
#[allow(clippy::arithmetic_side_effects)]
pub fn freivalds_span_check(
    a: &[i8],
    b: &[i8],
    claimed_c: &[i32],
    m: u16,
    k: u16,
    n: u16,
    challenge: [u32; 2],
) -> Result<u64, CertificateError> {
    let (mu, ku, nu) = (usize::from(m), usize::from(k), usize::from(n));
    if m == 0
        || k == 0
        || n == 0
        || a.len() != mu * ku
        || b.len() != ku * nu
        || claimed_c.len() != mu * nu
    {
        return Err(CertificateError::Shape);
    }
    let mut macs = 0u64;
    for r in challenge {
        let w: Vec<i128> = (0..nu)
            .map(|j| i128::from(r.rotate_left((j % 32) as u32)))
            .collect();
        let mut bw = vec![0i128; ku];
        for (q, slot) in bw.iter_mut().enumerate() {
            let mut acc = 0i128;
            for j in 0..nu {
                acc += i128::from(b[q * nu + j]) * w[j];
            }
            *slot = acc;
        }
        for i in 0..mu {
            let mut lhs = 0i128;
            for j in 0..nu {
                lhs += i128::from(claimed_c[i * nu + j]) * w[j];
            }
            let mut rhs = 0i128;
            for (q, bwq) in bw.iter().enumerate() {
                rhs += i128::from(a[i * ku + q]) * bwq;
            }
            if lhs != rhs {
                return Err(CertificateError::Relation);
            }
        }
        macs = macs
            .saturating_add((ku as u64).saturating_mul(nu as u64))
            .saturating_add((mu as u64).saturating_mul(nu as u64))
            .saturating_add((mu as u64).saturating_mul(ku as u64));
    }
    Ok(macs)
}

/// Freivalds admission path: binds the claimed transcript (requant
/// consistency, commitment, output hashes, projections) and then verifies
/// the span relation in `O(n^2)` — it never re-runs the full GEMM. A fully
/// self-consistent forged certificate over a wrong product passes every
/// binding check and dies exactly on [`CertificateError::Relation`]; the
/// re-derivation path [`admit_span_certificate`] must reject the same
/// forgery at its commitment gate.
#[allow(clippy::arithmetic_side_effects)] // u16 products fit usize exactly
pub fn admit_span_certificate_freivalds(
    cert: &SpanCertificate,
    a: &[i8],
    b: &[i8],
    claimed_c: &[i32],
    claimed_c8: &[i8],
) -> Result<(), CertificateError> {
    if cert.reps != 2 || cert.rbits != 32 {
        return Err(CertificateError::Soundness);
    }
    if claimed_c8.len() != usize::from(cert.m) * usize::from(cert.n) {
        return Err(CertificateError::Shape);
    }
    if requant_w8a8(claimed_c, cert.mult, cert.shift)?.as_slice() != claimed_c8 {
        return Err(CertificateError::Output);
    }
    let commitment = commit_span_transcript(
        a, b, claimed_c, claimed_c8, cert.m, cert.k, cert.n, cert.mult, cert.shift,
    );
    if commitment != cert.commitment {
        return Err(CertificateError::Commitment);
    }
    if cert.c32_hash != hash("NOOS/WEFT/W8A8/C32/V1", &ints_bytes(claimed_c))
        || cert.c8_hash != hash("NOOS/WEFT/W8A8/C8/V1", &i8_bytes(claimed_c8))
    {
        return Err(CertificateError::Output);
    }
    if project_span(claimed_c, cert.challenge) != cert.projections {
        return Err(CertificateError::Projection);
    }
    freivalds_span_check(a, b, claimed_c, cert.m, cert.k, cert.n, cert.challenge)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use noos_grain::{decode_formula, decode_subject, eval, Meter};
    #[test]
    fn compiles_and_runs() {
        let c = compile("fn inc(x: u64)->u64 ! {} cost 20 dec 0 { x + 1 }").unwrap();
        let b = decode_formula(&from_hex(&c.units[0].grain_formula_hex)).unwrap();
        let s = decode_subject(&encode_noun(&list_data(&[atom(4)]).unwrap())).unwrap();
        let mut m = Meter::new(1000, 1000);
        let v = eval(1, s, b, &mut m).unwrap();
        assert_eq!(v.as_atom(), Some(&[5][..]));
    }
    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn certificate_mutations_reject() {
        let a = vec![1i8; 16];
        let b = vec![2i8; 16];
        let c = gemm_i8(&a, &b, 4, 4, 4).unwrap();
        let c8 = requant_w8a8(&c, 1, 1).unwrap();
        let cert = derive_span_certificate(&a, &b, 4, 4, 4, 1, 1, [7, 9]).unwrap();
        assert_eq!(admit_span_certificate(&cert, &a, &b, &c, &c8), Ok(()));
        let mut bad = c.clone();
        bad[0] += 1;
        assert_eq!(
            admit_span_certificate(&cert, &a, &b, &bad, &c8),
            Err(CertificateError::Output)
        );
    }
}
