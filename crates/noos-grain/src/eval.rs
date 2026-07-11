//! The Grain v1 machine (spec §§7–10): explicit work-stack interpreter, no
//! host recursion, charge-before-reduction/allocation, deterministic traps.

use crate::noun::Noun;
use crate::{
    awords, GrainTrap, Meter, COST_APPLY, COST_ARM, COST_CELL_ALLOC, COST_COMPOSE, COST_CONS,
    COST_EDIT_BASE, COST_EDIT_STEP, COST_EQUAL_BASE, COST_EQUAL_NODE, COST_EQUAL_WORD, COST_IF,
    COST_INC_BASE, COST_INC_WORD, COST_ISCELL, COST_PUSH, COST_QUOTE, COST_SLOT_BASE,
    COST_SLOT_STEP, GRAIN_VERSION, MAX_ATOM_BYTES,
};

enum Task {
    Eval(Noun, Noun),
    Kont(K),
}

enum K {
    ConsMake,
    Apply,
    IsCell,
    Inc,
    Equal,
    If {
        subject: Noun,
        then_f: Noun,
        else_f: Noun,
    },
    Compose {
        formula: Noun,
    },
    Push {
        subject: Noun,
        formula: Noun,
    },
    Arm {
        axis: Noun,
    },
    Edit {
        axis: Noun,
    },
}

/// Lab-only jet hook surface. [`eval_with_jets`] recognizes `[12 id f]` and
/// offers the evaluation to the hook. A firing hook MUST reproduce the exact
/// observational triple of evaluating `f` on the subject — value-or-trap,
/// trap code, and metering — charging `meter` through the same frozen
/// schedule. Declining (`None`) falls back to interpreting `f`, so erasing
/// `[12 id f]` to `f` is always semantics-preserving, exactly like opcode
/// 11. Production [`eval`] passes no hook: opcode 12 stays `UNKNOWN_OPCODE`.
pub trait JetHook {
    /// `id` is pure data (never evaluated); return `None` to decline.
    fn dispatch(
        &self,
        id: &Noun,
        subject: &Noun,
        formula: &Noun,
        meter: &mut Meter,
    ) -> Option<Result<Noun, GrainTrap>>;
}

/// Pure deterministic evaluation (spec §1). The conformance triple is
/// `(value-or-trap, trap_code, meter.spent())`.
pub fn eval(
    version: u32,
    subject: Noun,
    formula: Noun,
    meter: &mut Meter,
) -> Result<Noun, GrainTrap> {
    eval_inner(version, subject, formula, meter, None)
}

/// [`eval`] with a lab-only jet hook: identical semantics except that
/// `[12 id f]` consults `hook` (see [`JetHook`]).
pub fn eval_with_jets(
    version: u32,
    subject: Noun,
    formula: Noun,
    meter: &mut Meter,
    hook: &dyn JetHook,
) -> Result<Noun, GrainTrap> {
    eval_inner(version, subject, formula, meter, Some(hook))
}

fn eval_inner(
    version: u32,
    subject: Noun,
    formula: Noun,
    meter: &mut Meter,
    hook: Option<&dyn JetHook>,
) -> Result<Noun, GrainTrap> {
    if version != GRAIN_VERSION {
        return Err(GrainTrap::UnknownVersion);
    }
    let mut tasks: Vec<Task> = vec![Task::Eval(subject, formula)];
    let mut vals: Vec<Noun> = Vec::new();

    while let Some(task) = tasks.pop() {
        match task {
            Task::Eval(s, f) => dispatch(s, f, &mut tasks, &mut vals, meter, hook)?,
            Task::Kont(k) => kont(k, &mut tasks, &mut vals, meter)?,
        }
    }

    debug_assert_eq!(vals.len(), 1);
    // Unreachable fallback: the machine pushes exactly one value per Eval.
    vals.pop().ok_or(GrainTrap::TypeMismatch)
}

/// Spec §8: shape validation (uncharged) → dispatch charge → schedule.
fn dispatch(
    s: Noun,
    f: Noun,
    tasks: &mut Vec<Task>,
    vals: &mut Vec<Noun>,
    meter: &mut Meter,
    hook: Option<&dyn JetHook>,
) -> Result<(), GrainTrap> {
    let (head, arg) = match f.as_cell() {
        Some((h, t)) => (h.clone(), t.clone()),
        None => return Err(GrainTrap::TypeMismatch),
    };

    // Cons composition: head is itself a formula cell.
    if head.is_cell() {
        meter.charge(COST_CONS)?;
        tasks.push(Task::Kont(K::ConsMake));
        tasks.push(Task::Eval(s.clone(), arg)); // tail formula, second
        tasks.push(Task::Eval(s, head)); // head formula, first
        return Ok(());
    }

    let op = match head.as_atom() {
        Some([]) => 0u8,
        Some(&[b]) if b <= 12 => b,
        _ => return Err(GrainTrap::UnknownOpcode),
    };

    match op {
        0 => {
            let axis = arg;
            check_axis(&axis)?;
            meter.charge(slot_cost(&axis))?;
            let r = walk(&s, &axis)?;
            vals.push(r);
        }
        1 => {
            meter.charge(COST_QUOTE)?;
            vals.push(arg);
        }
        2 => {
            let (b, c) = split(&arg)?;
            meter.charge(COST_APPLY)?;
            tasks.push(Task::Kont(K::Apply));
            tasks.push(Task::Eval(s.clone(), c)); // new formula, second
            tasks.push(Task::Eval(s, b)); // new subject, first
        }
        3 => {
            meter.charge(COST_ISCELL)?;
            tasks.push(Task::Kont(K::IsCell));
            tasks.push(Task::Eval(s, arg));
        }
        4 => {
            // All charges at completion (operand-size dependent).
            tasks.push(Task::Kont(K::Inc));
            tasks.push(Task::Eval(s, arg));
        }
        5 => {
            let (b, c) = split(&arg)?;
            tasks.push(Task::Kont(K::Equal));
            tasks.push(Task::Eval(s.clone(), c));
            tasks.push(Task::Eval(s, b));
        }
        6 => {
            let (b, cd) = split(&arg)?;
            let (c, d) = split(&cd)?;
            meter.charge(COST_IF)?;
            tasks.push(Task::Kont(K::If {
                subject: s.clone(),
                then_f: c,
                else_f: d,
            }));
            tasks.push(Task::Eval(s, b));
        }
        7 => {
            let (b, c) = split(&arg)?;
            meter.charge(COST_COMPOSE)?;
            tasks.push(Task::Kont(K::Compose { formula: c }));
            tasks.push(Task::Eval(s, b));
        }
        8 => {
            let (b, c) = split(&arg)?;
            meter.charge(COST_PUSH)?;
            tasks.push(Task::Kont(K::Push {
                subject: s.clone(),
                formula: c,
            }));
            tasks.push(Task::Eval(s, b));
        }
        9 => {
            let (b, c) = split(&arg)?;
            if b.is_cell() {
                return Err(GrainTrap::TypeMismatch);
            }
            check_axis(&b)?;
            meter.charge(COST_ARM)?;
            tasks.push(Task::Kont(K::Arm { axis: b }));
            tasks.push(Task::Eval(s, c));
        }
        10 => {
            let (bc, d) = split(&arg)?;
            let (b, c) = split(&bc)?;
            if b.is_cell() {
                return Err(GrainTrap::TypeMismatch);
            }
            check_axis(&b)?;
            // All charges at completion (axis-length dependent).
            tasks.push(Task::Kont(K::Edit { axis: b }));
            tasks.push(Task::Eval(s.clone(), d)); // old tree, second
            tasks.push(Task::Eval(s, c)); // replacement value, first
        }
        11 => {
            // [11 h f]: h is pure data, never evaluated; COST_HINT = 0.
            let (_hint, f2) = split(&arg)?;
            tasks.push(Task::Eval(s, f2));
        }
        12 => {
            // Lab-only jet hint: invalid in production (no hook), checked
            // BEFORE any shape validation so production behavior for every
            // `[12 ...]` formula is exactly `UNKNOWN_OPCODE`. With a hook,
            // `[12 id f]` mirrors opcode 11 (charge 0, `id` never
            // evaluated): the hook may produce the exact observational
            // triple of `f`, else `f` is interpreted.
            let Some(h) = hook else {
                return Err(GrainTrap::UnknownOpcode);
            };
            let (id, f2) = split(&arg)?;
            match h.dispatch(&id, &s, &f2, meter) {
                Some(r) => vals.push(r?),
                None => tasks.push(Task::Eval(s, f2)),
            }
        }
        _ => return Err(GrainTrap::UnknownOpcode), // unreachable: op <= 12
    }
    Ok(())
}

fn kont(
    k: K,
    tasks: &mut Vec<Task>,
    vals: &mut Vec<Noun>,
    meter: &mut Meter,
) -> Result<(), GrainTrap> {
    match k {
        K::ConsMake => {
            let tail = pop(vals);
            let head = pop(vals);
            let cell = alloc_cell(head, tail, meter)?;
            vals.push(cell);
        }
        K::Apply => {
            let f2 = pop(vals);
            let s2 = pop(vals);
            tasks.push(Task::Eval(s2, f2));
        }
        K::IsCell => {
            let v = pop(vals);
            vals.push(loobean(v.is_cell()));
        }
        K::Inc => {
            let a = pop(vals);
            let bytes = a.as_atom().ok_or(GrainTrap::TypeMismatch)?;
            meter.charge(
                COST_INC_BASE.saturating_add(awords(bytes.len()).saturating_mul(COST_INC_WORD)),
            )?;
            let mut r = bytes.to_vec();
            let mut carried = true;
            for b in r.iter_mut() {
                let (nb, overflow) = b.overflowing_add(1);
                *b = nb;
                if !overflow {
                    carried = false;
                    break;
                }
            }
            if carried {
                if r.len() >= MAX_ATOM_BYTES {
                    return Err(GrainTrap::AtomBound);
                }
                r.push(1);
            }
            let out = alloc_atom(r, meter)?;
            vals.push(out);
        }
        K::Equal => {
            let y = pop(vals);
            let x = pop(vals);
            meter.charge(COST_EQUAL_BASE)?;
            let eq = metered_eq(&x, &y, meter)?;
            vals.push(loobean(eq));
        }
        K::If {
            subject,
            then_f,
            else_f,
        } => {
            let cond = pop(vals);
            let branch = match cond.as_atom() {
                Some([]) => then_f,
                Some([1]) => else_f,
                _ => return Err(GrainTrap::TypeMismatch),
            };
            tasks.push(Task::Eval(subject, branch));
        }
        K::Compose { formula } => {
            let s2 = pop(vals);
            tasks.push(Task::Eval(s2, formula));
        }
        K::Push { subject, formula } => {
            let v = pop(vals);
            let s2 = alloc_cell(v, subject, meter)?;
            tasks.push(Task::Eval(s2, formula));
        }
        K::Arm { axis } => {
            let core = pop(vals);
            meter.charge(slot_cost(&axis))?;
            let f = walk(&core, &axis)?;
            tasks.push(Task::Eval(core, f));
        }
        K::Edit { axis } => {
            let t = pop(vals);
            let v = pop(vals);
            let out = edit(&axis, v, t, meter)?;
            vals.push(out);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Machine invariant: every Kont finds its operands on the value stack.
#[inline]
fn pop(vals: &mut Vec<Noun>) -> Noun {
    match vals.pop() {
        Some(v) => v,
        None => unreachable!("value stack underflow"),
    }
}

#[inline]
fn split(n: &Noun) -> Result<(Noun, Noun), GrainTrap> {
    match n.as_cell() {
        Some((h, t)) => Ok((h.clone(), t.clone())),
        None => Err(GrainTrap::TypeMismatch),
    }
}

/// Loobean result constants: canonical atoms, no allocation charge (spec §6).
#[inline]
fn loobean(yes: bool) -> Noun {
    if yes {
        Noun::atom_u64(0)
    } else {
        Noun::atom_u64(1)
    }
}

/// Axis operand must be an atom (TYPE_MISMATCH) and nonzero (INVALID_AXIS);
/// both checked before any charge (spec §8 step 5).
fn check_axis(axis: &Noun) -> Result<(), GrainTrap> {
    match axis.as_atom() {
        None => Err(GrainTrap::TypeMismatch),
        Some([]) => Err(GrainTrap::InvalidAxis),
        Some(_) => Ok(()),
    }
}

/// Bit length of a nonzero minimal-LE atom.
fn bits(bytes: &[u8]) -> u64 {
    debug_assert!(!bytes.is_empty());
    let top = *bytes.last().unwrap_or(&0);
    debug_assert!(top != 0);
    // u8::leading_zeros counts within 8 bits.
    ((bytes.len() as u64).saturating_sub(1))
        .saturating_mul(8)
        .saturating_add(8u64.saturating_sub(u64::from(top.leading_zeros())))
}

#[inline]
fn axis_bit(bytes: &[u8], i: u64) -> bool {
    let byte = bytes[(i / 8) as usize];
    (byte >> (i % 8)) & 1 == 1
}

/// Slot cost (spec §7): `COST_SLOT_BASE + (bits(axis) - 1) * COST_SLOT_STEP`.
fn slot_cost(axis: &Noun) -> u64 {
    let b = match axis.as_atom() {
        Some(bytes) => bits(bytes),
        None => unreachable!("slot_cost on a cell axis"),
    };
    COST_SLOT_BASE.saturating_add(b.saturating_sub(1).saturating_mul(COST_SLOT_STEP))
}

/// Axis walk (spec §7). The caller has already charged the slot cost.
fn walk(n: &Noun, axis: &Noun) -> Result<Noun, GrainTrap> {
    let bytes = axis.as_atom().ok_or(GrainTrap::TypeMismatch)?;
    if bytes.is_empty() {
        return Err(GrainTrap::InvalidAxis);
    }
    let nbits = bits(bytes);
    let mut cur = n.clone();
    let mut i = nbits.saturating_sub(1);
    while i > 0 {
        i = i.saturating_sub(1);
        let (h, t) = match cur.as_cell() {
            Some((h, t)) => (h.clone(), t.clone()),
            None => return Err(GrainTrap::InvalidAxis),
        };
        cur = if axis_bit(bytes, i) { t } else { h };
    }
    Ok(cur)
}

/// Allocation sequence (spec §6): charge → arena → depth check → construct.
fn alloc_cell(head: Noun, tail: Noun, meter: &mut Meter) -> Result<Noun, GrainTrap> {
    meter.charge(COST_CELL_ALLOC)?;
    meter.arena_add(COST_CELL_ALLOC)?;
    Noun::cell(head, tail)
}

/// Allocation sequence for an atom of minimal bytes `r`.
fn alloc_atom(r: Vec<u8>, meter: &mut Meter) -> Result<Noun, GrainTrap> {
    let w = 1u64.saturating_add(awords(r.len()));
    meter.charge(w)?;
    meter.arena_add(w)?;
    Ok(Noun::atom_from_minimal(r))
}

/// Opcode 5 comparison walk with the frozen charge schedule (spec §9 op 5).
fn metered_eq(x: &Noun, y: &Noun, meter: &mut Meter) -> Result<bool, GrainTrap> {
    let mut stack: Vec<(Noun, Noun)> = vec![(x.clone(), y.clone())];
    while let Some((p, q)) = stack.pop() {
        meter.charge(COST_EQUAL_NODE)?;
        match (p.as_atom(), q.as_atom()) {
            (Some(a), Some(b)) => {
                if a.len() != b.len() {
                    return Ok(false);
                }
                meter.charge(awords(a.len()).saturating_mul(COST_EQUAL_WORD))?;
                if a != b {
                    return Ok(false);
                }
            }
            (None, None) => {
                let (ph, pt) = split(&p)?;
                let (qh, qt) = split(&q)?;
                stack.push((pt, qt));
                stack.push((ph, qh)); // heads compared first
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// Opcode 10 completion (spec §9 op 10).
fn edit(axis: &Noun, v: Noun, t: Noun, meter: &mut Meter) -> Result<Noun, GrainTrap> {
    let bytes = axis.as_atom().ok_or(GrainTrap::TypeMismatch)?;
    if bytes.is_empty() {
        return Err(GrainTrap::InvalidAxis);
    }
    let levels = bits(bytes).saturating_sub(1);
    // 1. Bulk charge: base + per-level (walk step + that level's cell).
    meter.charge(COST_EDIT_BASE.saturating_add(levels.saturating_mul(COST_EDIT_STEP)))?;
    // 2. Walk, recording (sibling, went_tail) per level.
    let mut path: Vec<(Noun, bool)> = Vec::with_capacity(levels as usize);
    let mut cur = t;
    let mut i = levels;
    while i > 0 {
        i = i.saturating_sub(1);
        let (h, tl) = match cur.as_cell() {
            Some((h, tl)) => (h.clone(), tl.clone()),
            None => return Err(GrainTrap::InvalidAxis),
        };
        if axis_bit(bytes, i) {
            path.push((h, true));
            cur = tl;
        } else {
            path.push((tl, false));
            cur = h;
        }
    }
    // 3. Arena words for the rebuilt spine.
    meter.arena_add(levels.saturating_mul(COST_CELL_ALLOC))?;
    // 4. Rebuild bottom-up; each new cell's depth is checked.
    let mut acc = v;
    for (sibling, went_tail) in path.into_iter().rev() {
        acc = if went_tail {
            Noun::cell(sibling, acc)?
        } else {
            Noun::cell(acc, sibling)?
        };
    }
    Ok(acc)
}
