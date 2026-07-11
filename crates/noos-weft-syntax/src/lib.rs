//! Parser and static semantics for the frozen Weft v1 candidate grammar.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub span: Span,
    pub message: String,
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}-{}: {}",
            self.code, self.span.start, self.span.end, self.message
        )
    }
}
impl std::error::Error for Diagnostic {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    Open,
    Commit,
    Beacon,
    Dream,
    Sealed(String),
}
impl Effect {
    pub fn canonical(&self) -> String {
        match self {
            Self::Open => "open".into(),
            Self::Commit => "commit".into(),
            Self::Beacon => "beacon".into(),
            Self::Dream => "dream".into(),
            Self::Sealed(f) => format!("sealed({f})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Int { signed: bool, bits: u16 },
    Bool,
    Bytes(Size),
    Hash,
    Address,
    Tuple(Vec<Type>),
    Vec(Box<Type>, Size),
    Tensor(Box<Type>, Vec<Size>, String),
    Linear(Box<Type>),
    Rights(Box<Type>, BTreeSet<String>),
    Committed(Box<Type>, String),
    Rand256(String),
    Dream(Box<Type>),
    Named(String),
    Unit,
}
impl Type {
    #[must_use]
    pub fn is_linear(&self) -> bool {
        matches!(self, Self::Linear(_))
    }
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Int { signed, bits } => format!("{}{bits}", if *signed { 'i' } else { 'u' }),
            Self::Bool => "Bool".into(),
            Self::Bytes(n) => format!("Bytes<{}>", n.canonical()),
            Self::Hash => "Hash".into(),
            Self::Address => "Address".into(),
            Self::Tuple(ts) => format!(
                "({})",
                ts.iter().map(Type::canonical).collect::<Vec<_>>().join(",")
            ),
            Self::Vec(t, n) => format!("Vec<{},{}>", t.canonical(), n.canonical()),
            Self::Tensor(t, ns, p) => format!(
                "Tensor<{},[{}],@{}>",
                t.canonical(),
                ns.iter().map(Size::canonical).collect::<Vec<_>>().join(","),
                p
            ),
            Self::Linear(t) => format!("lin {}", t.canonical()),
            Self::Rights(t, r) => format!(
                "{} & rights {{{}}}",
                t.canonical(),
                r.iter().cloned().collect::<Vec<_>>().join(",")
            ),
            Self::Committed(t, h) => format!("Committed<{},{}>", t.canonical(), h),
            Self::Rand256(h) => format!("Rand256<{h}>"),
            Self::Dream(t) => format!("Dream<{}>", t.canonical()),
            Self::Named(n) => n.clone(),
            Self::Unit => "()".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Size {
    Lit(u64),
    Var(String),
    Add(Box<Size>, Box<Size>),
    Mul(Box<Size>, Box<Size>),
    Max(Box<Size>, Box<Size>),
    Ceil(Box<Size>, u64),
}
impl Size {
    pub fn canonical(&self) -> String {
        match self {
            Self::Lit(v) => v.to_string(),
            Self::Var(v) => v.clone(),
            Self::Add(a, b) => format!("({}+{})", a.canonical(), b.canonical()),
            Self::Mul(a, b) => format!("({}*{})", a.canonical(), b.canonical()),
            Self::Max(a, b) => format!("max({},{})", a.canonical(), b.canonical()),
            Self::Ceil(a, d) => format!("ceil({}/{d})", a.canonical()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    MatMul,
    Eq,
    Lt,
    Shl,
    Shr,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprKind {
    Var(String),
    Int(u64),
    Bool(bool),
    Tuple(Vec<Expr>),
    Let(String, Box<Expr>, Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Consume(Box<Expr>),
    Field(Box<Expr>, String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: Type,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub sizes: Vec<String>,
    pub params: Vec<Param>,
    pub ret: Type,
    pub effects: BTreeSet<Effect>,
    pub cost: Option<Size>,
    pub dec: Option<Size>,
    pub body: Expr,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub functions: Vec<Function>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokKind {
    Id(String),
    Num(u64),
    Arrow,
    EqEq,
    Shl,
    Shr,
    Sym(char),
    Eof,
}
#[derive(Clone, Debug)]
struct Tok {
    k: TokKind,
    s: Span,
}
fn lex(src: &str) -> Result<Vec<Tok>, Diagnostic> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i = i.saturating_add(1);
            continue;
        }
        if b[i] == b'-' && b.get(i.saturating_add(1)) == Some(&b'-') {
            while i < b.len() && b[i] != b'\n' {
                i = i.saturating_add(1)
            }
            continue;
        }
        let st = i;
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            i = i.saturating_add(1);
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i = i.saturating_add(1)
            }
            out.push(Tok {
                k: TokKind::Id(src[st..i].into()),
                s: Span { start: st, end: i },
            });
            continue;
        }
        if b[i].is_ascii_digit() {
            i = i.saturating_add(1);
            while i < b.len() && b[i].is_ascii_digit() {
                i = i.saturating_add(1)
            }
            let n = src[st..i].parse().map_err(|_| Diagnostic {
                code: "E-PARSE-002",
                span: Span { start: st, end: i },
                message: "integer literal exceeds u64".into(),
            })?;
            out.push(Tok {
                k: TokKind::Num(n),
                s: Span { start: st, end: i },
            });
            continue;
        }
        let (k, n) = match b[i] {
            b'-' if b.get(i.saturating_add(1)) == Some(&b'>') => (TokKind::Arrow, 2),
            b'=' if b.get(i.saturating_add(1)) == Some(&b'=') => (TokKind::EqEq, 2),
            b'<' if b.get(i.saturating_add(1)) == Some(&b'<') => (TokKind::Shl, 2),
            b'>' if b.get(i.saturating_add(1)) == Some(&b'>') => (TokKind::Shr, 2),
            c if b"(){}[]<>,:;!+*-=&.@".contains(&c) => (TokKind::Sym(c as char), 1),
            _ => {
                return Err(Diagnostic {
                    code: "E-LEX-001",
                    span: Span {
                        start: i,
                        end: i.saturating_add(1),
                    },
                    message: "unexpected source byte".into(),
                })
            }
        };
        i = i.saturating_add(n);
        out.push(Tok {
            k,
            s: Span { start: st, end: i },
        })
    }
    out.push(Tok {
        k: TokKind::Eof,
        s: Span { start: i, end: i },
    });
    Ok(out)
}
struct Parser {
    t: Vec<Tok>,
    i: usize,
}
impl Parser {
    fn cur(&self) -> &Tok {
        &self.t[self.i]
    }
    fn bump(&mut self) -> Tok {
        let x = self.t[self.i].clone();
        self.i = self.i.saturating_add(1);
        x
    }
    fn err<T>(&self, msg: &str) -> Result<T, Diagnostic> {
        Err(Diagnostic {
            code: "E-PARSE-001",
            span: self.cur().s,
            message: msg.into(),
        })
    }
    fn sym(&mut self, c: char) -> bool {
        if self.cur().k == TokKind::Sym(c) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn need_sym(&mut self, c: char) -> Result<(), Diagnostic> {
        if self.sym(c) {
            Ok(())
        } else {
            self.err(&format!("expected '{c}'"))
        }
    }
    fn id(&mut self) -> Result<String, Diagnostic> {
        match self.bump() {
            Tok {
                k: TokKind::Id(v), ..
            } => Ok(v),
            x => Err(Diagnostic {
                code: "E-PARSE-001",
                span: x.s,
                message: "expected identifier".into(),
            }),
        }
    }
    fn kw(&mut self, k: &str) -> bool {
        if matches!(&self.cur().k,TokKind::Id(x) if x==k) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn program(&mut self) -> Result<Program, Diagnostic> {
        let mut functions = Vec::new();
        while self.cur().k != TokKind::Eof {
            functions.push(self.function()?)
        }
        if functions.is_empty() {
            return self.err("source contains no functions");
        }
        Ok(Program { functions })
    }
    fn function(&mut self) -> Result<Function, Diagnostic> {
        let st = self.cur().s.start;
        if !self.kw("fn") {
            return self.err("expected 'fn'");
        }
        let name = self.id()?;
        let mut sizes = Vec::new();
        if self.sym('<') {
            loop {
                let n = self.id()?;
                if self.sym(':') && !self.kw("Size") {
                    return self.err("size parameter must have kind Size");
                }
                sizes.push(n);
                if self.sym('>') {
                    break;
                }
                self.need_sym(',')?
            }
        }
        self.need_sym('(')?;
        let mut params = Vec::new();
        if !self.sym(')') {
            loop {
                let ps = self.cur().s.start;
                let n = self.id()?;
                self.need_sym(':')?;
                let ty = self.ty()?;
                params.push(Param {
                    name: n,
                    ty,
                    span: Span {
                        start: ps,
                        end: self.cur().s.start,
                    },
                });
                if self.sym(')') {
                    break;
                }
                self.need_sym(',')?
            }
        }
        if self.bump().k != TokKind::Arrow {
            return self.err("expected '->'");
        }
        let ret = self.ty()?;
        let mut effects = BTreeSet::new();
        if self.sym('!') {
            self.need_sym('{')?;
            if !self.sym('}') {
                loop {
                    let e = self.id()?;
                    effects.insert(match e.as_str() {
                        "open" => Effect::Open,
                        "commit" => Effect::Commit,
                        "beacon" => Effect::Beacon,
                        "dream" => Effect::Dream,
                        "sealed" => {
                            self.need_sym('(')?;
                            let f = self.id()?;
                            self.need_sym(')')?;
                            Effect::Sealed(f)
                        }
                        _ => return self.err("unknown effect"),
                    });
                    if self.sym('}') {
                        break;
                    }
                    self.need_sym(',')?
                }
            }
        }
        let cost = if self.kw("cost") {
            Some(self.size()?)
        } else {
            None
        };
        let dec = if self.kw("dec") {
            Some(self.size()?)
        } else {
            None
        };
        self.need_sym('{')?;
        let body = self.expr(0)?;
        self.need_sym('}')?;
        Ok(Function {
            name,
            sizes,
            params,
            ret,
            effects,
            cost,
            dec,
            body,
            span: Span {
                start: st,
                end: self.cur().s.start,
            },
        })
    }
    fn ty(&mut self) -> Result<Type, Diagnostic> {
        if self.kw("lin") {
            return Ok(Type::Linear(Box::new(self.ty()?)));
        }
        if self.sym('(') {
            if self.sym(')') {
                return Ok(Type::Unit);
            }
            let mut ts = vec![self.ty()?];
            while self.sym(',') {
                ts.push(self.ty()?)
            }
            self.need_sym(')')?;
            return Ok(Type::Tuple(ts));
        }
        let n = self.id()?;
        let mut ty = match n.as_str() {
            "Bool" => Type::Bool,
            "Hash" => Type::Hash,
            "Address" => Type::Address,
            "u8" => Type::Int {
                signed: false,
                bits: 8,
            },
            "u16" => Type::Int {
                signed: false,
                bits: 16,
            },
            "u32" => Type::Int {
                signed: false,
                bits: 32,
            },
            "u64" => Type::Int {
                signed: false,
                bits: 64,
            },
            "u128" => Type::Int {
                signed: false,
                bits: 128,
            },
            "i8" => Type::Int {
                signed: true,
                bits: 8,
            },
            "i16" => Type::Int {
                signed: true,
                bits: 16,
            },
            "i32" => Type::Int {
                signed: true,
                bits: 32,
            },
            "i64" => Type::Int {
                signed: true,
                bits: 64,
            },
            "i128" => Type::Int {
                signed: true,
                bits: 128,
            },
            "Bytes" => {
                self.need_sym('<')?;
                let s = self.size()?;
                self.need_sym('>')?;
                Type::Bytes(s)
            }
            "Vec" => {
                self.need_sym('<')?;
                let t = self.ty()?;
                self.need_sym(',')?;
                let s = self.size()?;
                self.need_sym('>')?;
                Type::Vec(Box::new(t), s)
            }
            "Tensor" => {
                self.need_sym('<')?;
                let element = self.ty()?;
                self.need_sym(',')?;
                self.need_sym('[')?;
                let mut dimensions = Vec::new();
                if !self.sym(']') {
                    loop {
                        dimensions.push(self.size()?);
                        if self.sym(']') {
                            break;
                        }
                        self.need_sym(',')?;
                    }
                }
                self.need_sym(',')?;
                self.need_sym('@')?;
                let mut profile = self.id()?;
                if self.sym('.') {
                    profile.push('.');
                    profile.push_str(&self.id()?);
                }
                self.need_sym('>')?;
                Type::Tensor(Box::new(element), dimensions, profile)
            }
            "Committed" => {
                self.need_sym('<')?;
                let t = self.ty()?;
                self.need_sym(',')?;
                let h = self.id()?;
                self.need_sym('>')?;
                Type::Committed(Box::new(t), h)
            }
            "Rand256" => {
                self.need_sym('<')?;
                let h = self.id()?;
                self.need_sym('>')?;
                Type::Rand256(h)
            }
            "Dream" => {
                self.need_sym('<')?;
                let t = self.ty()?;
                self.need_sym('>')?;
                Type::Dream(Box::new(t))
            }
            _ => Type::Named(n),
        };
        if self.sym('&') {
            if !self.kw("rights") {
                return self.err("expected rights row");
            }
            self.need_sym('{')?;
            let mut rs = BTreeSet::new();
            if !self.sym('}') {
                loop {
                    let right = self.id()?;
                    if !rs.insert(right.clone()) {
                        return Err(Diagnostic {
                            code: "E-RIGHT-003",
                            span: self.cur().s,
                            message: format!("ambiguous duplicate right '{right}'"),
                        });
                    }
                    if self.sym('}') {
                        break;
                    }
                    self.need_sym(',')?
                }
            }
            ty = Type::Rights(Box::new(ty), rs)
        }
        Ok(ty)
    }
    fn size(&mut self) -> Result<Size, Diagnostic> {
        let mut x = match self.bump() {
            Tok {
                k: TokKind::Num(n), ..
            } => Size::Lit(n),
            Tok {
                k: TokKind::Id(v), ..
            } => Size::Var(v),
            z => {
                return Err(Diagnostic {
                    code: "E-PARSE-001",
                    span: z.s,
                    message: "expected size expression".into(),
                })
            }
        };
        while matches!(self.cur().k, TokKind::Sym('+') | TokKind::Sym('*')) {
            let op = self.bump().k;
            let y = match self.bump() {
                Tok {
                    k: TokKind::Num(n), ..
                } => Size::Lit(n),
                Tok {
                    k: TokKind::Id(v), ..
                } => Size::Var(v),
                z => {
                    return Err(Diagnostic {
                        code: "E-PARSE-001",
                        span: z.s,
                        message: "expected size operand".into(),
                    })
                }
            };
            x = if op == TokKind::Sym('+') {
                Size::Add(Box::new(x), Box::new(y))
            } else {
                Size::Mul(Box::new(x), Box::new(y))
            }
        }
        Ok(x)
    }
    fn expr(&mut self, min: u8) -> Result<Expr, Diagnostic> {
        let st = self.cur().s.start;
        let mut x = if self.kw("let") {
            let n = self.id()?;
            self.need_sym('=')?;
            let v = self.expr(0)?;
            self.need_sym(';')?;
            let b = self.expr(0)?;
            Expr {
                kind: ExprKind::Let(n, Box::new(v), Box::new(b.clone())),
                span: Span {
                    start: st,
                    end: b.span.end,
                },
            }
        } else if self.kw("if") {
            let c = self.expr(0)?;
            self.need_sym('{')?;
            let a = self.expr(0)?;
            self.need_sym('}')?;
            if !self.kw("else") {
                return self.err("if requires else");
            };
            self.need_sym('{')?;
            let b = self.expr(0)?;
            self.need_sym('}')?;
            Expr {
                kind: ExprKind::If(Box::new(c), Box::new(a), Box::new(b)),
                span: Span {
                    start: st,
                    end: self.cur().s.start,
                },
            }
        } else if self.sym('(') {
            if self.sym(')') {
                Expr {
                    kind: ExprKind::Tuple(vec![]),
                    span: Span {
                        start: st,
                        end: self.cur().s.start,
                    },
                }
            } else {
                let first = self.expr(0)?;
                if self.sym(',') {
                    let mut xs = vec![first];
                    loop {
                        xs.push(self.expr(0)?);
                        if self.sym(')') {
                            break;
                        }
                        self.need_sym(',')?
                    }
                    Expr {
                        kind: ExprKind::Tuple(xs),
                        span: Span {
                            start: st,
                            end: self.cur().s.start,
                        },
                    }
                } else {
                    self.need_sym(')')?;
                    first
                }
            }
        } else {
            match self.bump() {
                Tok {
                    k: TokKind::Num(n),
                    s,
                } => Expr {
                    kind: ExprKind::Int(n),
                    span: s,
                },
                Tok {
                    k: TokKind::Id(n),
                    s,
                } if n == "true" || n == "false" => Expr {
                    kind: ExprKind::Bool(n == "true"),
                    span: s,
                },
                Tok {
                    k: TokKind::Id(n),
                    s,
                } => Expr {
                    kind: ExprKind::Var(n),
                    span: s,
                },
                z => {
                    return Err(Diagnostic {
                        code: "E-PARSE-001",
                        span: z.s,
                        message: "expected expression".into(),
                    })
                }
            }
        };
        loop {
            if self.sym('(') {
                let name = if let ExprKind::Var(n) = &x.kind {
                    n.clone()
                } else {
                    return self.err("only named calls are supported");
                };
                let mut a = Vec::new();
                if !self.sym(')') {
                    loop {
                        a.push(self.expr(0)?);
                        if self.sym(')') {
                            break;
                        }
                        self.need_sym(',')?
                    }
                }
                x = Expr {
                    kind: if name == "consume" && a.len() == 1 {
                        ExprKind::Consume(Box::new(a.remove(0)))
                    } else {
                        ExprKind::Call(name, a)
                    },
                    span: Span {
                        start: st,
                        end: self.cur().s.start,
                    },
                };
                continue;
            }
            if self.sym('.') {
                let f = self.id()?;
                x = Expr {
                    kind: ExprKind::Field(Box::new(x), f),
                    span: Span {
                        start: st,
                        end: self.cur().s.start,
                    },
                };
                continue;
            }
            let (op, p) = match self.cur().k {
                TokKind::Sym('+') => (BinOp::Add, 10),
                TokKind::Sym('-') => (BinOp::Sub, 10),
                TokKind::Sym('*') => (BinOp::Mul, 20),
                TokKind::Sym('@') => (BinOp::MatMul, 20),
                TokKind::EqEq => (BinOp::Eq, 5),
                TokKind::Sym('<') => (BinOp::Lt, 5),
                TokKind::Shl => (BinOp::Shl, 8),
                TokKind::Shr => (BinOp::Shr, 8),
                _ => break,
            };
            if p < min {
                break;
            }
            self.bump();
            let y = self.expr(p.saturating_add(1))?;
            let end = y.span.end;
            x = Expr {
                kind: ExprKind::Binary(op, Box::new(x), Box::new(y)),
                span: Span { start: st, end },
            }
        }
        Ok(x)
    }
}
pub fn parse(src: &str) -> Result<Program, Vec<Diagnostic>> {
    let t = match lex(src) {
        Ok(t) => t,
        Err(e) => return Err(vec![e]),
    };
    let mut p = Parser { t, i: 0 };
    p.program().map_err(|e| vec![e])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedFunction {
    pub function: Function,
    pub inferred_effects: BTreeSet<Effect>,
    pub inferred_cost: u64,
}
#[derive(Clone, Debug)]
struct Info {
    ty: Type,
    e: BTreeSet<Effect>,
    cost: u64,
    used: BTreeSet<String>,
}
fn merge(a: &Info, b: &Info) -> BTreeSet<String> {
    a.used.union(&b.used).cloned().collect()
}
fn infer(
    e: &Expr,
    env: &BTreeMap<String, Type>,
    fns: &BTreeMap<String, (Vec<Type>, Type, BTreeSet<Effect>)>,
) -> Result<Info, Diagnostic> {
    let bad = |code, msg: String| Diagnostic {
        code,
        span: e.span,
        message: msg,
    };
    match &e.kind {
        ExprKind::Var(n) => {
            let ty = env
                .get(n)
                .cloned()
                .ok_or_else(|| bad("E-TYPE-001", format!("unbound name '{n}'")))?;
            let mut used = BTreeSet::new();
            if ty.is_linear() {
                used.insert(n.clone());
            }
            Ok(Info {
                ty,
                e: BTreeSet::new(),
                cost: 2,
                used,
            })
        }
        ExprKind::Int(_) => Ok(Info {
            ty: Type::Int {
                signed: false,
                bits: 64,
            },
            e: BTreeSet::new(),
            cost: 1,
            used: BTreeSet::new(),
        }),
        ExprKind::Bool(_) => Ok(Info {
            ty: Type::Bool,
            e: BTreeSet::new(),
            cost: 1,
            used: BTreeSet::new(),
        }),
        ExprKind::Tuple(xs) => {
            let mut ts = Vec::new();
            let mut ef = BTreeSet::new();
            let mut used = BTreeSet::new();
            let mut c: u64 = 4;
            for x in xs {
                let q = infer(x, env, fns)?;
                if !used.is_disjoint(&q.used) {
                    return Err(bad("E-LIN-002", "linear value used more than once".into()));
                }
                used.extend(q.used);
                ef.extend(q.e);
                c = c.saturating_add(q.cost);
                ts.push(q.ty)
            }
            Ok(Info {
                ty: if ts.is_empty() {
                    Type::Unit
                } else {
                    Type::Tuple(ts)
                },
                e: ef,
                cost: c,
                used,
            })
        }
        ExprKind::Let(n, a, b) => {
            let ia = infer(a, env, fns)?;
            let mut en = env.clone();
            en.insert(n.clone(), ia.ty.clone());
            let ib = infer(b, &en, fns)?;
            if ia.ty.is_linear() && !ib.used.contains(n) {
                return Err(bad(
                    "E-LIN-001",
                    format!("linear binding '{n}' is not consumed"),
                ));
            }
            // The bound name's own consumption belongs to the body scope;
            // any *other* linear resource used by both the value and the
            // body is a double use.
            let mut body_used = ib.used.clone();
            body_used.remove(n);
            if !ia.used.is_disjoint(&body_used) {
                return Err(bad("E-LIN-002", "linear value used more than once".into()));
            }
            let mut used = ia.used.clone();
            used.extend(body_used);
            Ok(Info {
                ty: ib.ty,
                e: ia.e.union(&ib.e).cloned().collect(),
                cost: ia.cost.saturating_add(ib.cost).saturating_add(3),
                used,
            })
        }
        ExprKind::If(c, a, b) => {
            let ic = infer(c, env, fns)?;
            if ic.ty != Type::Bool {
                return Err(bad("E-TYPE-003", "if condition is not Bool".into()));
            }
            let ia = infer(a, env, fns)?;
            let ib = infer(b, env, fns)?;
            if ia.ty != ib.ty {
                return Err(bad("E-TYPE-004", "if branches have different types".into()));
            }
            if ia.used != ib.used {
                return Err(bad(
                    "E-LIN-003",
                    "if branches consume different linear resources".into(),
                ));
            }
            let used = merge(&ic, &ia);
            if !ic.used.is_disjoint(&ia.used) {
                return Err(bad("E-LIN-002", "linear condition reused in branch".into()));
            }
            Ok(Info {
                ty: ia.ty,
                e: ic.e.union(&ia.e).chain(ib.e.iter()).cloned().collect(),
                cost: ic
                    .cost
                    .saturating_add(ia.cost.max(ib.cost))
                    .saturating_add(3),
                used,
            })
        }
        ExprKind::Binary(op, a, b) => {
            let ia = infer(a, env, fns)?;
            let ib = infer(b, env, fns)?;
            if !ia.used.is_disjoint(&ib.used) {
                return Err(bad("E-LIN-002", "linear value used twice".into()));
            }
            let ty = if matches!(op, BinOp::MatMul) {
                match (&ia.ty, &ib.ty) {
                    (
                        Type::Tensor(left_element, left_shape, left_profile),
                        Type::Tensor(right_element, right_shape, right_profile),
                    ) if matches!(
                        left_element.as_ref(),
                        Type::Int {
                            signed: true,
                            bits: 8
                        }
                    ) && matches!(
                        right_element.as_ref(),
                        Type::Int {
                            signed: true,
                            bits: 8
                        }
                    ) && left_shape.len() == 2
                        && right_shape.len() == 2
                        && left_shape[1] == right_shape[0]
                        && left_profile == right_profile =>
                    {
                        Type::Tensor(
                            Box::new(Type::Int {
                                signed: true,
                                bits: 32,
                            }),
                            vec![left_shape[0].clone(), right_shape[1].clone()],
                            format!("{left_profile}.accum"),
                        )
                    }
                    _ => {
                        return Err(bad(
                            "E-PROFILE-001",
                            "matmul requires compatible i8 tensors under one numeric profile"
                                .into(),
                        ))
                    }
                }
            } else {
                let ty = match op {
                    BinOp::Eq | BinOp::Lt => Type::Bool,
                    _ => ia.ty.clone(),
                };
                if matches!(op, BinOp::Eq) {
                    if ia.ty != ib.ty {
                        return Err(bad("E-TYPE-005", "equality operands differ".into()));
                    }
                } else if !matches!(ia.ty, Type::Int { .. }) || !matches!(ib.ty, Type::Int { .. }) {
                    return Err(bad(
                        "E-TYPE-006",
                        "arithmetic requires integer operands".into(),
                    ));
                }
                ty
            };
            Ok(Info {
                ty,
                e: ia.e.union(&ib.e).cloned().collect(),
                cost: ia.cost.saturating_add(ib.cost).saturating_add(4),
                used: merge(&ia, &ib),
            })
        }
        ExprKind::Consume(x) => {
            let i = infer(x, env, fns)?;
            if !i.ty.is_linear() {
                return Err(bad("E-LIN-004", "consume requires lin value".into()));
            }
            Ok(Info {
                ty: Type::Unit,
                e: i.e,
                cost: i.cost.saturating_add(1),
                used: i.used,
            })
        }
        ExprKind::Call(n, args) => {
            let mut infos = Vec::new();
            for a in args {
                infos.push(infer(a, env, fns)?)
            }
            let mut used = BTreeSet::new();
            let mut ef = BTreeSet::new();
            let mut cost: u64 = 4;
            for i in &infos {
                if !used.is_disjoint(&i.used) {
                    return Err(bad("E-LIN-002", "linear argument reused".into()));
                }
                used.extend(i.used.clone());
                ef.extend(i.e.clone());
                cost = cost.saturating_add(i.cost)
            }
            match n.as_str() {
                "commit" => {
                    if infos.len() != 1 {
                        return Err(bad("E-TYPE-007", "commit takes one argument".into()));
                    }
                    ef.insert(Effect::Commit);
                    Ok(Info {
                        ty: Type::Committed(Box::new(infos[0].ty.clone()), "derived".into()),
                        e: ef,
                        cost: cost.saturating_add(8),
                        used,
                    })
                }
                "beacon" => {
                    if infos.len() != 1 {
                        return Err(bad("E-TYPE-007", "beacon takes one argument".into()));
                    }
                    let h = if let Type::Committed(_, h) = &infos[0].ty {
                        h.clone()
                    } else {
                        return Err(bad(
                            "E-EFFECT-002",
                            "beacon requires a Committed token".into(),
                        ));
                    };
                    ef.insert(Effect::Beacon);
                    Ok(Info {
                        ty: Type::Rand256(h),
                        e: ef,
                        cost: cost.saturating_add(8),
                        used,
                    })
                }
                "declassify" => {
                    ef.insert(Effect::Open);
                    if infos.len() != 2 {
                        return Err(bad(
                            "E-RIGHT-001",
                            "declassify requires value and rights proof".into(),
                        ));
                    }
                    Ok(Info {
                        ty: match &infos[0].ty {
                            Type::Rights(t, r) if r.contains("Disclose") => *t.clone(),
                            _ => return Err(bad("E-RIGHT-002", "missing Disclose right".into())),
                        },
                        e: ef,
                        cost: cost.saturating_add(8),
                        used,
                    })
                }
                _ => {
                    let Some((ps, r, fe)) = fns.get(n) else {
                        return Err(bad("E-TYPE-008", format!("unknown function '{n}'")));
                    };
                    if ps.len() != infos.len() {
                        return Err(bad("E-TYPE-009", "call arity mismatch".into()));
                    }
                    for (p, a) in ps.iter().zip(&infos) {
                        if p != &a.ty && !matches!((p, &a.ty), (Type::Int { .. }, Type::Int { .. }))
                        {
                            return Err(bad("E-TYPE-010", "call argument type mismatch".into()));
                        }
                    }
                    ef.extend(fe.clone());
                    Ok(Info {
                        ty: r.clone(),
                        e: ef,
                        cost: cost.saturating_add(4),
                        used,
                    })
                }
            }
        }
        ExprKind::Field(_, _) => Err(bad(
            "E-TYPE-011",
            "field projection requires declared struct metadata".into(),
        )),
    }
}
const MAX_RIGHTS_ROW_WIDTH: usize = 16;
const MAX_RIGHTS_TYPE_DEPTH: usize = 128;

fn validate_type(ty: &Type, span: Span, diagnostics: &mut Vec<Diagnostic>) {
    validate_type_at_depth(ty, span, diagnostics, 0)
}

fn validate_type_at_depth(ty: &Type, span: Span, diagnostics: &mut Vec<Diagnostic>, depth: usize) {
    if depth > MAX_RIGHTS_TYPE_DEPTH {
        diagnostics.push(Diagnostic {
            code: "E-RIGHT-004",
            span,
            message: "rights carrier nesting exceeds the decidable v1 budget".into(),
        });
        return;
    }
    let next_depth = depth.saturating_add(1);
    match ty {
        Type::Tensor(element, dimensions, profile) => {
            let element_ok = match profile.as_str() {
                "W8A8v1" => matches!(
                    element.as_ref(),
                    Type::Int {
                        signed: true,
                        bits: 8
                    }
                ),
                "W8A8v1.accum" => matches!(
                    element.as_ref(),
                    Type::Int {
                        signed: true,
                        bits: 32
                    }
                ),
                _ => {
                    diagnostics.push(Diagnostic {
                        code: "E-PROFILE-002",
                        span,
                        message: format!("unknown numeric profile '@{profile}'"),
                    });
                    false
                }
            };
            if !element_ok {
                diagnostics.push(Diagnostic {
                    code: "E-PROFILE-003",
                    span,
                    message: "tensor element type conflicts with numeric profile".into(),
                })
            }
            if dimensions
                .iter()
                .any(|dimension| matches!(dimension, Size::Lit(0 | 65_536..)))
            {
                diagnostics.push(Diagnostic {
                    code: "E-PROFILE-004",
                    span,
                    message: "tensor dimensions must fit the nonzero 16-bit transcript fields"
                        .into(),
                })
            }
            validate_type_at_depth(element, span, diagnostics, next_depth)
        }
        Type::Tuple(elements) => {
            for element in elements {
                validate_type_at_depth(element, span, diagnostics, next_depth)
            }
        }
        Type::Rights(element, rights) => {
            if rights.is_empty() || rights.len() > MAX_RIGHTS_ROW_WIDTH {
                diagnostics.push(Diagnostic {
                    code: "E-RIGHT-004",
                    span,
                    message: "rights row is empty or exceeds the v1 width budget".into(),
                });
            }
            validate_type_at_depth(element, span, diagnostics, next_depth)
        }
        Type::Vec(element, _)
        | Type::Linear(element)
        | Type::Committed(element, _)
        | Type::Dream(element) => validate_type_at_depth(element, span, diagnostics, next_depth),
        _ => {}
    }
}

pub fn check(p: &Program) -> Result<Vec<CheckedFunction>, Vec<Diagnostic>> {
    let mut ds = Vec::new();
    let mut seen = BTreeSet::new();
    let mut fns = BTreeMap::new();
    for f in &p.functions {
        if !seen.insert(f.name.clone()) {
            ds.push(Diagnostic {
                code: "E-TYPE-012",
                span: f.span,
                message: "duplicate function".into(),
            });
            continue;
        }
        fns.insert(
            f.name.clone(),
            (
                f.params.iter().map(|p| p.ty.clone()).collect(),
                f.ret.clone(),
                f.effects.clone(),
            ),
        );
    }
    let mut out = Vec::new();
    for f in &p.functions {
        for parameter in &f.params {
            validate_type(&parameter.ty, parameter.span, &mut ds)
        }
        validate_type(&f.ret, f.span, &mut ds);
        let env = f
            .params
            .iter()
            .map(|p| (p.name.clone(), p.ty.clone()))
            .collect();
        match infer(&f.body, &env, &fns) {
            Ok(i) => {
                for p in &f.params {
                    if p.ty.is_linear() && !i.used.contains(&p.name) {
                        ds.push(Diagnostic {
                            code: "E-LIN-001",
                            span: p.span,
                            message: format!("linear parameter '{}' is not consumed", p.name),
                        })
                    }
                }
                if i.ty != f.ret && !matches!((&i.ty, &f.ret), (Type::Int { .. }, Type::Int { .. }))
                {
                    ds.push(Diagnostic {
                        code: "E-TYPE-002",
                        span: f.body.span,
                        message: format!(
                            "return type is {}, expected {}",
                            i.ty.canonical(),
                            f.ret.canonical()
                        ),
                    })
                }
                if !i.e.is_subset(&f.effects) {
                    ds.push(Diagnostic {
                        code: "E-EFFECT-001",
                        span: f.span,
                        message: "inferred effects exceed declared row".into(),
                    })
                }
                if contains_self_call(&f.body, &f.name) {
                    ds.push(Diagnostic {
                        code: if f.dec.is_none() {
                            "E-TOT-001"
                        } else {
                            "E-TOT-002"
                        },
                        span: f.span,
                        message: if f.dec.is_none() {
                            "recursive function lacks dec measure".into()
                        } else {
                            "recursive call does not carry a statically smaller size argument"
                                .into()
                        },
                    })
                }
                if let Some(Size::Lit(bound)) = &f.cost {
                    if i.cost > *bound {
                        ds.push(Diagnostic {
                            code: "E-COST-001",
                            span: f.span,
                            message: format!("declared cost {bound} below derived {}", i.cost),
                        })
                    }
                }
                out.push(CheckedFunction {
                    function: f.clone(),
                    inferred_effects: i.e,
                    inferred_cost: i.cost,
                })
            }
            Err(e) => ds.push(e),
        }
    }
    if ds.is_empty() {
        Ok(out)
    } else {
        ds.sort_by_key(|d| (d.span.start, d.code));
        Err(ds)
    }
}
fn contains_self_call(e: &Expr, name: &str) -> bool {
    match &e.kind {
        ExprKind::Call(n, a) => n == name || a.iter().any(|x| contains_self_call(x, name)),
        ExprKind::Tuple(x) => x.iter().any(|x| contains_self_call(x, name)),
        ExprKind::Let(_, a, b) | ExprKind::Binary(_, a, b) => {
            contains_self_call(a, name) || contains_self_call(b, name)
        }
        ExprKind::If(c, a, b) => {
            contains_self_call(c, name)
                || contains_self_call(a, name)
                || contains_self_call(b, name)
        }
        ExprKind::Consume(x) | ExprKind::Field(x, _) => contains_self_call(x, name),
        _ => false,
    }
}

/// Stable canonical AST bytes used for `source_root`.
pub fn canonical_program(p: &Program) -> Vec<u8> {
    let mut s = String::new();
    for f in &p.functions {
        s.push_str("fn ");
        s.push_str(&f.name);
        s.push('<');
        s.push_str(&f.sizes.join(","));
        s.push_str(">(");
        for (i, p) in f.params.iter().enumerate() {
            if i > 0 {
                s.push(',')
            }
            s.push_str(&p.name);
            s.push(':');
            s.push_str(&p.ty.canonical())
        }
        s.push_str(")->");
        s.push_str(&f.ret.canonical());
        s.push('!');
        s.push_str(
            &f.effects
                .iter()
                .map(Effect::canonical)
                .collect::<Vec<_>>()
                .join(","),
        );
        if let Some(c) = &f.cost {
            s.push_str(" cost ");
            s.push_str(&c.canonical())
        }
        if let Some(d) = &f.dec {
            s.push_str(" dec ");
            s.push_str(&d.canonical())
        }
        s.push('{');
        canonical_expr(&f.body, &mut s);
        s.push('}')
    }
    s.into_bytes()
}
fn canonical_expr(e: &Expr, s: &mut String) {
    match &e.kind {
        ExprKind::Var(n) => s.push_str(n),
        ExprKind::Int(n) => s.push_str(&n.to_string()),
        ExprKind::Bool(v) => s.push_str(if *v { "true" } else { "false" }),
        ExprKind::Tuple(xs) => {
            s.push('(');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    s.push(',')
                }
                canonical_expr(x, s)
            }
            s.push(')')
        }
        ExprKind::Let(n, a, b) => {
            s.push_str("let ");
            s.push_str(n);
            s.push('=');
            canonical_expr(a, s);
            s.push(';');
            canonical_expr(b, s)
        }
        ExprKind::If(c, a, b) => {
            s.push_str("if ");
            canonical_expr(c, s);
            s.push('{');
            canonical_expr(a, s);
            s.push_str("}else{");
            canonical_expr(b, s);
            s.push('}')
        }
        ExprKind::Call(n, a) => {
            s.push_str(n);
            s.push('(');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    s.push(',')
                }
                canonical_expr(x, s)
            }
            s.push(')')
        }
        ExprKind::Binary(op, a, b) => {
            s.push('(');
            canonical_expr(a, s);
            s.push_str(match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Eq => "==",
                BinOp::MatMul => "@",
                BinOp::Lt => "<",
                BinOp::Shl => "<<",
                BinOp::Shr => ">>",
            });
            canonical_expr(b, s);
            s.push(')')
        }
        ExprKind::Consume(x) => {
            s.push_str("consume(");
            canonical_expr(x, s);
            s.push(')')
        }
        ExprKind::Field(x, n) => {
            canonical_expr(x, s);
            s.push('.');
            s.push_str(n)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    #[test]
    fn checks_effect_and_linear() {
        let p = parse("fn ok(x: lin Hash) -> () ! {} cost 10 dec 0 { consume(x) }").unwrap();
        assert!(check(&p).is_ok());
        let p = parse("fn bad(x: lin Hash) -> () ! {} { () }").unwrap();
        assert_eq!(check(&p).unwrap_err()[0].code, "E-LIN-001");
    }
    #[test]
    fn checks_profiles_effects_and_totality() {
        let profile = parse(
            "fn keep<m: Size>(x: Tensor<i8,[m,8],@W8A8v1>) -> Tensor<i8,[m,8],@W8A8v1> { x }",
        )
        .unwrap();
        assert!(check(&profile).is_ok());
        let unknown =
            parse("fn bad(x: Tensor<i8,[8,8],@Unknown>) -> Tensor<i8,[8,8],@Unknown> { x }")
                .unwrap();
        assert!(check(&unknown)
            .unwrap_err()
            .iter()
            .any(|diagnostic| diagnostic.code == "E-PROFILE-002"));
        let recursive = parse("fn f(x: u64)->u64 dec 1 { f(x) }").unwrap();
        assert!(check(&recursive)
            .unwrap_err()
            .iter()
            .any(|diagnostic| diagnostic.code == "E-TOT-002"));
        let beacon = parse("fn f(x: u64)->Rand256<h> ! {beacon} { beacon(x) }").unwrap();
        assert_eq!(check(&beacon).unwrap_err()[0].code, "E-EFFECT-002");
    }

    #[test]
    fn canonical_ignores_comments() {
        let a = parse("fn f(x: u64)->u64 { x + 1 }").unwrap();
        let b = parse("--x\n fn f ( x : u64 ) -> u64 {x+1}").unwrap();
        assert_eq!(canonical_program(&a), canonical_program(&b));
    }
}
