//! The frozen RV32 lowering ABI (`noos/jet/rv32-lowering-v1`).
//!
//! # Frozen ABI, version 1
//!
//! - **Instruction subset** (RV32I integer only, closed): `LUI`, `ADDI`,
//!   `ADD`, `SUB`, `XOR`, `OR`, `AND`, `SLTU`, `LW`, `SW`, `BEQ`, `BNE`,
//!   `JAL`, `ECALL`. Any other encoding is an illegal-instruction trap in
//!   the reference interpreter.
//! - **Memory map**: text at `0x0000_0000` (word `i` at `4 * i`), subject
//!   leaves at [`SUBJECT_BASE`] (leaf `i` is the little-endian u32 word at
//!   `SUBJECT_BASE + 4 * i`), and an operand stack growing down from
//!   [`STACK_TOP`]. Data access is valid only word-aligned inside
//!   `[SUBJECT_BASE, STACK_TOP)`.
//! - **Registers**: `x0` zero, `x2` stack pointer, `x5`/`x6` scratch,
//!   `x10` (`a0`) result value, `x11` (`a1`) result status.
//! - **Exit**: `ECALL` halts. `a1 == 0` means `a0` is the result value;
//!   `a1 == 1` is a DOMAIN EXIT (`a0 == 0`): the input left the lowered
//!   domain and the host MUST fall back to Grain interpretation. A lowered
//!   image never answers wrongly — it either matches Grain exactly or
//!   domain-exits.
//!
//! # Lowered formula subset
//!
//! Subjects are right-nested tuples of `leaf_count` u32 atoms
//! ([`subject_noun`]). Formulas are the closed integer grammar:
//! `[0 axis]` (a leaf axis of the declared tuple shape), `[1 c]` (a u32
//! constant), `[4 f]` (increment; wrap past `2^32 - 1` domain-exits),
//! `[5 f g]` (equality producing the Grain loobean 0/1), and `[6 b c d]`
//! (if; a non-loobean condition domain-exits where Grain would trap
//! `TYPE_MISMATCH`).
//!
//! # Equality law (tested on the golden vectors and a random corpus)
//!
//! For every lowered formula `F` and every subject in the declared shape:
//! `status == 0` implies Grain `eval(1, subject, F)` returns exactly the
//! atom `value` — a lowered image NEVER answers wrongly. `status == 1`
//! carries no result claim: it marks the run outside the lowered domain
//! (a non-loobean condition, or any intermediate increment past
//! `2^32 - 1`, even when the final Grain value would fit u32) and the
//! host MUST interpret instead.
//!
//! Lowering is **deterministic**: the same formula and leaf count always
//! produce byte-identical images, pinned by the committed golden vectors
//! and the exact [`Rv32Image::image_id`] hash.
//!
//! Metering note: RV32 images are proof-lowering artifacts. Consensus
//! metering stays Grain's; an image computes values, never charges.

use core::fmt;

use noos_grain::Noun;

/// Frozen ABI version (hashed into every image id).
pub const RV32_ABI_VERSION: u32 = 1;
/// Base address of the subject leaf words.
pub const SUBJECT_BASE: u32 = 0x0001_0000;
/// Initial stack pointer; the operand stack grows down.
pub const STACK_TOP: u32 = 0x0002_0000;
/// Maximum declared tuple width (keeps every leaf axis well below u32).
pub const MAX_LEAVES: u32 = 24;

const CTX_IMAGE: &[u8] = b"noosphere.jet.rv32.image.v1";

// Register numbers (frozen).
const X0: u32 = 0;
const SP: u32 = 2;
const T0: u32 = 5;
const T1: u32 = 6;
const A0: u32 = 10;
const A1: u32 = 11;

/// Why a formula cannot be lowered. Lowering failure is NOT an error of the
/// jet system — unsupported formulas simply stay on the interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowerError {
    /// The formula (or a subformula) is not a cell.
    FormulaNotACell,
    /// Head opcode outside the frozen `{0, 1, 4, 5, 6}` grammar (cons
    /// composition included: results must stay u32 atoms).
    UnsupportedOpcode,
    /// `[0 axis]` axis is not a leaf of the declared tuple shape.
    UnsupportedAxis,
    /// `[1 c]` constant is a cell or wider than 4 bytes.
    ConstTooWide,
    /// `leaf_count` outside `1..=MAX_LEAVES`.
    LeafCountOutOfRange,
    /// Formula nesting beyond the frozen depth bound (64).
    TooDeep,
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            LowerError::FormulaNotACell => "formula is not a cell",
            LowerError::UnsupportedOpcode => "opcode outside the lowered grammar",
            LowerError::UnsupportedAxis => "axis is not a declared tuple leaf",
            LowerError::ConstTooWide => "constant does not fit u32",
            LowerError::LeafCountOutOfRange => "leaf count outside 1..=MAX_LEAVES",
            LowerError::TooDeep => "formula nesting beyond the frozen bound",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for LowerError {}

/// A lowered, immutable RV32 image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rv32Image {
    /// Instruction words, in execution order at text base 0.
    pub words: Vec<u32>,
    /// Declared subject tuple width.
    pub leaf_count: u32,
}

impl Rv32Image {
    /// Little-endian byte serialization of the text segment.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len().saturating_mul(4));
        for w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Exact image id: BLAKE3 over the ABI version, the declared leaf
    /// count, the word count, and the text bytes.
    #[must_use]
    pub fn image_id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(CTX_IMAGE);
        h.update(&RV32_ABI_VERSION.to_le_bytes());
        h.update(&self.leaf_count.to_le_bytes());
        h.update(
            &u32::try_from(self.words.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        h.update(&self.bytes());
        *h.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Instruction encoding (RV32I). Shifts/masks are bounded field packing; the
// wrapping forms are the ISA definition.
// ---------------------------------------------------------------------------

#[allow(clippy::arithmetic_side_effects)]
fn enc_r(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

#[allow(clippy::arithmetic_side_effects)]
fn enc_i(imm: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

#[allow(clippy::arithmetic_side_effects)]
fn enc_s(imm: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    (((imm >> 5) & 0x7F) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm & 0x1F) << 7)
        | opcode
}

#[allow(clippy::arithmetic_side_effects)]
fn enc_b(imm: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3F) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xF) << 8)
        | (((imm >> 11) & 1) << 7)
        | opcode
}

#[allow(clippy::arithmetic_side_effects)]
fn enc_u(imm20: u32, rd: u32, opcode: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | opcode
}

#[allow(clippy::arithmetic_side_effects)]
fn enc_j(imm: u32, rd: u32, opcode: u32) -> u32 {
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3FF) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xFF) << 12)
        | (rd << 7)
        | opcode
}

fn addi(rd: u32, rs1: u32, imm: u32) -> u32 {
    enc_i(imm, rs1, 0b000, rd, 0x13)
}

fn lw(rd: u32, rs1: u32, imm: u32) -> u32 {
    enc_i(imm, rs1, 0b010, rd, 0x03)
}

fn sw(rs2: u32, rs1: u32, imm: u32) -> u32 {
    enc_s(imm, rs2, rs1, 0b010, 0x23)
}

const ECALL: u32 = 0x0000_0073;

// ---------------------------------------------------------------------------
// Deterministic codegen
// ---------------------------------------------------------------------------

struct Asm {
    words: Vec<u32>,
    /// `JAL x0` sites to patch to the shared DOMAIN EXIT label.
    domain_exits: Vec<usize>,
}

impl Asm {
    fn emit(&mut self, w: u32) -> usize {
        let at = self.words.len();
        self.words.push(w);
        at
    }

    // Branch/jump offsets: word-index deltas times 4, within ±2^11 words
    // for every lowered formula (bounded by the depth cap).
    #[allow(clippy::arithmetic_side_effects)]
    fn branch_offset(at: usize, target: usize) -> u32 {
        let delta = (target as i64 - at as i64) * 4;
        (delta as i32) as u32
    }

    fn patch_beq(&mut self, at: usize, target: usize, rs1: u32, rs2: u32) {
        if let Some(w) = self.words.get_mut(at) {
            *w = enc_b(Asm::branch_offset(at, target), rs2, rs1, 0b000, 0x63);
        }
    }

    fn patch_jal(&mut self, at: usize, target: usize) {
        if let Some(w) = self.words.get_mut(at) {
            *w = enc_j(Asm::branch_offset(at, target), X0, 0x6F);
        }
    }

    /// `li rd, imm` as the frozen LUI+ADDI pair (always two words, so
    /// codegen is shape-deterministic regardless of the value).
    #[allow(clippy::arithmetic_side_effects)]
    fn li(&mut self, rd: u32, imm: u32) {
        let hi = imm.wrapping_add(0x800) >> 12;
        let lo = imm & 0xFFF;
        self.emit(enc_u(hi, rd, 0x37));
        self.emit(addi(rd, rd, lo));
    }

    /// Push t0 onto the operand stack.
    fn push_t0(&mut self) {
        self.emit(addi(SP, SP, 0xFFC)); // sp -= 4
        self.emit(sw(T0, SP, 0));
    }

    /// Pop the operand stack into `rd`.
    fn pop(&mut self, rd: u32) {
        self.emit(lw(rd, SP, 0));
        self.emit(addi(SP, SP, 4));
    }
}

/// Axis of leaf `i` in a right-nested tuple of `n` leaves (the declared
/// subject shape of the lowering ABI).
#[must_use]
pub fn axis_of_leaf(i: u32, n: u32) -> u64 {
    if n == 1 {
        1
    } else if i.saturating_add(1) == n {
        // All-tail path: 2^n - 1.
        (1u64 << n.min(63)).saturating_sub(1)
    } else {
        // i tails then one head: 2^(i+2) - 2.
        (1u64 << i.saturating_add(2).min(63)).saturating_sub(2)
    }
}

/// Atom value as u64 if it fits 8 bytes.
fn atom_u64_of(n: &Noun) -> Option<u64> {
    let bytes = n.as_atom()?;
    if bytes.len() > 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
    Some(u64::from_le_bytes(buf))
}

/// Atom value as u32 if it fits 4 bytes.
fn atom_u32_of(n: &Noun) -> Option<u32> {
    let bytes = n.as_atom()?;
    if bytes.len() > 4 {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
    Some(u32::from_le_bytes(buf))
}

fn gen(f: &Noun, asm: &mut Asm, leaf_count: u32, depth: u32) -> Result<(), LowerError> {
    if depth > 64 {
        return Err(LowerError::TooDeep);
    }
    let (head, arg) = f.as_cell().ok_or(LowerError::FormulaNotACell)?;
    if head.is_cell() {
        return Err(LowerError::UnsupportedOpcode);
    }
    let op = atom_u64_of(head).ok_or(LowerError::UnsupportedOpcode)?;
    let next = depth.saturating_add(1);
    match op {
        0 => {
            let axis = atom_u64_of(arg).ok_or(LowerError::UnsupportedAxis)?;
            let leaf = (0..leaf_count)
                .find(|i| axis_of_leaf(*i, leaf_count) == axis)
                .ok_or(LowerError::UnsupportedAxis)?;
            let addr = SUBJECT_BASE.saturating_add(leaf.saturating_mul(4));
            asm.li(T0, addr);
            asm.emit(lw(T0, T0, 0));
            asm.push_t0();
        }
        1 => {
            let c = atom_u32_of(arg).ok_or(LowerError::ConstTooWide)?;
            asm.li(T0, c);
            asm.push_t0();
        }
        4 => {
            gen(arg, asm, leaf_count, next)?;
            asm.pop(T0);
            asm.emit(addi(T0, T0, 1));
            // Wrap to zero == increment past 2^32 - 1: domain exit.
            asm.emit(enc_b(8, X0, T0, 0b001, 0x63)); // BNE t0, x0, +8
            let j = asm.emit(0); // JAL -> DOMAIN (patched)
            asm.domain_exits.push(j);
            asm.push_t0();
        }
        5 => {
            let (b, c) = arg.as_cell().ok_or(LowerError::FormulaNotACell)?;
            gen(b, asm, leaf_count, next)?;
            gen(c, asm, leaf_count, next)?;
            asm.pop(T1);
            asm.pop(T0);
            asm.emit(enc_r(0, T1, T0, 0b100, T0, 0x33)); // XOR t0, t0, t1
            asm.emit(enc_r(0, T0, X0, 0b011, T0, 0x33)); // SLTU t0, x0, t0
            asm.push_t0();
        }
        6 => {
            let (b, cd) = arg.as_cell().ok_or(LowerError::FormulaNotACell)?;
            let (c, d) = cd.as_cell().ok_or(LowerError::FormulaNotACell)?;
            gen(b, asm, leaf_count, next)?;
            asm.pop(T0);
            let beq_then = asm.emit(0); // BEQ t0, x0 -> THEN (patched)
            asm.emit(addi(T1, X0, 1));
            let beq_else = asm.emit(0); // BEQ t0, t1 -> ELSE (patched)
            let j = asm.emit(0); // non-loobean: JAL -> DOMAIN (patched)
            asm.domain_exits.push(j);
            let then_at = asm.words.len();
            asm.patch_beq(beq_then, then_at, T0, X0);
            gen(c, asm, leaf_count, next)?;
            let jal_end = asm.emit(0); // JAL -> END (patched)
            let else_at = asm.words.len();
            asm.patch_beq(beq_else, else_at, T0, T1);
            gen(d, asm, leaf_count, next)?;
            let end_at = asm.words.len();
            asm.patch_jal(jal_end, end_at);
        }
        _ => return Err(LowerError::UnsupportedOpcode),
    }
    Ok(())
}

/// Deterministic lowering of `formula` for subjects of `leaf_count` u32
/// leaves. Same inputs, byte-identical image, always.
pub fn lower(formula: &Noun, leaf_count: u32) -> Result<Rv32Image, LowerError> {
    if leaf_count == 0 || leaf_count > MAX_LEAVES {
        return Err(LowerError::LeafCountOutOfRange);
    }
    let mut asm = Asm {
        words: Vec::new(),
        domain_exits: Vec::new(),
    };
    asm.li(SP, STACK_TOP);
    gen(formula, &mut asm, leaf_count, 0)?;
    asm.pop(A0);
    asm.emit(addi(A1, X0, 0));
    asm.emit(ECALL);
    let domain_at = asm.words.len();
    asm.emit(addi(A0, X0, 0));
    asm.emit(addi(A1, X0, 1));
    asm.emit(ECALL);
    let sites = core::mem::take(&mut asm.domain_exits);
    for site in sites {
        asm.patch_jal(site, domain_at);
    }
    Ok(Rv32Image {
        words: asm.words,
        leaf_count,
    })
}

// ---------------------------------------------------------------------------
// Reference interpreter
// ---------------------------------------------------------------------------

/// Deterministic execution trap: every malformed image or access is a
/// stable, typed rejection (never host UB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rv32Trap {
    IllegalInstruction { pc: u32, word: u32 },
    MisalignedAccess { addr: u32 },
    AccessOutOfRange { addr: u32 },
    PcOutOfRange { pc: u32 },
    StepBound,
    InputArity { expected: u32, got: u32 },
}

impl fmt::Display for Rv32Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rv32Trap::IllegalInstruction { pc, word } => {
                write!(f, "illegal instruction {word:#010x} at pc {pc:#010x}")
            }
            Rv32Trap::MisalignedAccess { addr } => write!(f, "misaligned access {addr:#010x}"),
            Rv32Trap::AccessOutOfRange { addr } => write!(f, "access out of range {addr:#010x}"),
            Rv32Trap::PcOutOfRange { pc } => write!(f, "pc out of range {pc:#010x}"),
            Rv32Trap::StepBound => f.write_str("step bound exceeded"),
            Rv32Trap::InputArity { expected, got } => {
                write!(
                    f,
                    "input arity mismatch: expected {expected} leaves, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for Rv32Trap {}

/// Halted execution: the ABI journal is `(status, value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rv32Exit {
    pub status: u32,
    pub value: u32,
    pub steps: u64,
}

/// Execute `image` on `leaves` for at most `max_steps` instructions.
/// Wrapping arithmetic and shift-field extraction are the ISA semantics;
/// all quantities are bounded by construction.
#[allow(clippy::arithmetic_side_effects)]
pub fn execute(image: &Rv32Image, leaves: &[u32], max_steps: u64) -> Result<Rv32Exit, Rv32Trap> {
    let got = u32::try_from(leaves.len()).unwrap_or(u32::MAX);
    if got != image.leaf_count {
        return Err(Rv32Trap::InputArity {
            expected: image.leaf_count,
            got,
        });
    }
    let mut regs = [0u32; 32];
    let mut data: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    for (i, leaf) in leaves.iter().enumerate() {
        data.insert(SUBJECT_BASE + 4 * (i as u32), *leaf);
    }
    let mut pc: u32 = 0;
    let mut steps: u64 = 0;

    let load = |data: &std::collections::BTreeMap<u32, u32>, addr: u32| -> Result<u32, Rv32Trap> {
        if !addr.is_multiple_of(4) {
            return Err(Rv32Trap::MisalignedAccess { addr });
        }
        if !(SUBJECT_BASE..STACK_TOP).contains(&addr) {
            return Err(Rv32Trap::AccessOutOfRange { addr });
        }
        Ok(data.get(&addr).copied().unwrap_or(0))
    };

    loop {
        steps += 1;
        if steps > max_steps {
            return Err(Rv32Trap::StepBound);
        }
        if !pc.is_multiple_of(4) {
            return Err(Rv32Trap::PcOutOfRange { pc });
        }
        let idx = (pc / 4) as usize;
        let word = *image.words.get(idx).ok_or(Rv32Trap::PcOutOfRange { pc })?;

        let opcode = word & 0x7F;
        let rd = (word >> 7) & 0x1F;
        let funct3 = (word >> 12) & 0x7;
        let rs1 = (word >> 15) & 0x1F;
        let rs2 = (word >> 20) & 0x1F;
        let funct7 = word >> 25;
        let imm_i = ((word as i32) >> 20) as u32; // sign-extended
        let v1 = regs[rs1 as usize];
        let v2 = regs[rs2 as usize];
        let mut next_pc = pc.wrapping_add(4);
        let mut wr: Option<(u32, u32)> = None;

        match opcode {
            0x37 => wr = Some((rd, word & 0xFFFF_F000)), // LUI
            0x13 if funct3 == 0b000 => wr = Some((rd, v1.wrapping_add(imm_i))), // ADDI
            0x33 => {
                let val = match (funct3, funct7) {
                    (0b000, 0x00) => v1.wrapping_add(v2), // ADD
                    (0b000, 0x20) => v1.wrapping_sub(v2), // SUB
                    (0b100, 0x00) => v1 ^ v2,             // XOR
                    (0b110, 0x00) => v1 | v2,             // OR
                    (0b111, 0x00) => v1 & v2,             // AND
                    (0b011, 0x00) => u32::from(v1 < v2),  // SLTU
                    _ => return Err(Rv32Trap::IllegalInstruction { pc, word }),
                };
                wr = Some((rd, val));
            }
            0x03 if funct3 == 0b010 => {
                // LW
                let addr = v1.wrapping_add(imm_i);
                wr = Some((rd, load(&data, addr)?));
            }
            0x23 if funct3 == 0b010 => {
                // SW
                let imm_s = ((((word >> 25) << 5) | ((word >> 7) & 0x1F)) as i32)
                    .wrapping_shl(20)
                    .wrapping_shr(20) as u32;
                let addr = v1.wrapping_add(imm_s);
                if !addr.is_multiple_of(4) {
                    return Err(Rv32Trap::MisalignedAccess { addr });
                }
                if !(SUBJECT_BASE..STACK_TOP).contains(&addr) {
                    return Err(Rv32Trap::AccessOutOfRange { addr });
                }
                data.insert(addr, v2);
            }
            0x63 => {
                // BEQ / BNE
                let imm_b = ((((word >> 31) & 1) << 12)
                    | (((word >> 7) & 1) << 11)
                    | (((word >> 25) & 0x3F) << 5)
                    | (((word >> 8) & 0xF) << 1)) as i32;
                let imm_b = (imm_b << 19) >> 19; // sign-extend 13 bits
                let take = match funct3 {
                    0b000 => v1 == v2,
                    0b001 => v1 != v2,
                    _ => return Err(Rv32Trap::IllegalInstruction { pc, word }),
                };
                if take {
                    next_pc = pc.wrapping_add(imm_b as u32);
                }
            }
            0x6F => {
                // JAL
                let imm_j = ((((word >> 31) & 1) << 20)
                    | (((word >> 12) & 0xFF) << 12)
                    | (((word >> 20) & 1) << 11)
                    | (((word >> 21) & 0x3FF) << 1)) as i32;
                let imm_j = (imm_j << 11) >> 11; // sign-extend 21 bits
                wr = Some((rd, pc.wrapping_add(4)));
                next_pc = pc.wrapping_add(imm_j as u32);
            }
            0x73 if word == ECALL => {
                return Ok(Rv32Exit {
                    status: regs[A1 as usize],
                    value: regs[A0 as usize],
                    steps,
                });
            }
            _ => return Err(Rv32Trap::IllegalInstruction { pc, word }),
        }

        if let Some((r, v)) = wr {
            if r != 0 {
                regs[r as usize] = v;
            }
        }
        pc = next_pc;
    }
}

// ---------------------------------------------------------------------------
// Subject shape helpers
// ---------------------------------------------------------------------------

/// The right-nested tuple noun for `leaves` (the declared subject shape).
/// Empty input yields atom 0 (never produced by a valid lowering).
#[must_use]
pub fn subject_noun(leaves: &[u32]) -> Noun {
    let mut iter = leaves.iter().rev();
    let Some(last) = iter.next() else {
        return Noun::atom_u64(0);
    };
    let mut acc = Noun::atom_u64(u64::from(*last));
    for leaf in iter {
        acc = match Noun::cell(Noun::atom_u64(u64::from(*leaf)), acc) {
            Ok(c) => c,
            // Depth bound unreachable for <= MAX_LEAVES leaves.
            Err(_) => return Noun::atom_u64(0),
        };
    }
    acc
}

/// Host-side domain guard: `subject` as exactly `leaf_count` u32 leaves in
/// the declared right-nested shape, or `None` (fall back to Grain).
#[must_use]
pub fn leaves_from_subject(subject: &Noun, leaf_count: u32) -> Option<Vec<u32>> {
    let n = usize::try_from(leaf_count).ok()?;
    if n == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    let mut cur = subject.clone();
    for _ in 0..n.saturating_sub(1) {
        let (h, t) = cur.as_cell().map(|(h, t)| (h.clone(), t.clone()))?;
        out.push(atom_u32_of(&h)?);
        cur = t;
    }
    out.push(atom_u32_of(&cur)?);
    Some(out)
}
