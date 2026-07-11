//! The admitted native jets. Each mirrors the frozen Grain charge schedule
//! (spec §§6–10) instruction by instruction: same charge amounts, same
//! charge ORDER, same trap points, same arena accounting — so the
//! observational triple `(value-or-trap, trap_code, spent)` plus
//! `arena_used` is bit-identical to interpretation on every input,
//! including mid-schedule meter exhaustion.

use noos_grain::{
    awords, GrainTrap, Meter, Noun, COST_EQUAL_BASE, COST_EQUAL_NODE, COST_EQUAL_WORD,
    COST_INC_BASE, COST_INC_WORD, COST_SLOT_BASE, COST_SLOT_STEP, MAX_ATOM_BYTES,
};

/// Versioned implementation tag of the increment jet.
pub const INC_IMPL_TAG: &str = "noos-jet/native/inc/v1";
/// Versioned implementation tag of the tree-equality jet.
pub const TREE_EQ_IMPL_TAG: &str = "noos-jet/native/tree-eq/v1";

fn c2(h: Noun, t: Noun) -> Noun {
    match Noun::cell(h, t) {
        Ok(n) => n,
        // The frozen jet formulas are depth 2–3; the bound is unreachable.
        Err(_) => Noun::atom_u64(0),
    }
}

/// The bounded-field increment formula: `[4 [0 1]]` (increment the subject).
#[must_use]
pub fn inc_formula() -> Noun {
    c2(Noun::atom_u64(4), c2(Noun::atom_u64(0), Noun::atom_u64(1)))
}

/// The tree-equality formula: `[5 [0 2] [0 3]]` (head == tail).
#[must_use]
pub fn tree_eq_formula() -> Noun {
    c2(
        Noun::atom_u64(5),
        c2(
            c2(Noun::atom_u64(0), Noun::atom_u64(2)),
            c2(Noun::atom_u64(0), Noun::atom_u64(3)),
        ),
    )
}

/// Native `[4 [0 1]]`. Charge trace mirrored from the interpreter:
/// 1. `[0 1]` dispatch: `slot_cost(1) = COST_SLOT_BASE` (bits(1) == 1);
///    the axis-1 walk returns the whole subject and cannot fail.
/// 2. `K::Inc`: operand must be an atom (`TYPE_MISMATCH` after the slot
///    charge), then `COST_INC_BASE + awords(len) * COST_INC_WORD`.
/// 3. Carry past `MAX_ATOM_BYTES` is `ATOM_BOUND` before allocation.
/// 4. Atom allocation: `w = 1 + awords(result_len)` charged to both the
///    step meter and the arena.
pub fn jet_inc(subject: &Noun, meter: &mut Meter) -> Result<Noun, GrainTrap> {
    meter.charge(COST_SLOT_BASE)?;
    let bytes = subject.as_atom().ok_or(GrainTrap::TypeMismatch)?;
    meter
        .charge(COST_INC_BASE.saturating_add(awords(bytes.len()).saturating_mul(COST_INC_WORD)))?;
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
    let w = 1u64.saturating_add(awords(r.len()));
    meter.charge(w)?;
    meter.arena_add(w)?;
    Ok(Noun::atom_from_le_bytes(&r))
}

/// Native `[5 [0 2] [0 3]]`. Charge trace mirrored from the interpreter:
/// 1. `[0 2]` dispatch: `slot_cost(2) = COST_SLOT_BASE + COST_SLOT_STEP`;
///    the walk descends one level, so an atom subject is `INVALID_AXIS`
///    after that charge.
/// 2. `[0 3]`: identical slot charge; the walk cannot fail any more.
/// 3. `K::Equal`: `COST_EQUAL_BASE`, then the frozen comparison walk —
///    `COST_EQUAL_NODE` per node, `awords * COST_EQUAL_WORD` per equal-length
///    atom pair (heads pushed last, compared first), early exit on the first
///    difference. The loobean result never charges an allocation.
pub fn jet_tree_eq(subject: &Noun, meter: &mut Meter) -> Result<Noun, GrainTrap> {
    let slot = COST_SLOT_BASE.saturating_add(COST_SLOT_STEP);
    meter.charge(slot)?;
    let (head, tail) = match subject.as_cell() {
        Some((h, t)) => (h.clone(), t.clone()),
        None => return Err(GrainTrap::InvalidAxis),
    };
    meter.charge(slot)?;
    meter.charge(COST_EQUAL_BASE)?;

    let mut eq = true;
    let mut stack: Vec<(Noun, Noun)> = vec![(head, tail)];
    while let Some((p, q)) = stack.pop() {
        meter.charge(COST_EQUAL_NODE)?;
        match (p.as_atom(), q.as_atom()) {
            (Some(x), Some(y)) => {
                if x.len() != y.len() {
                    eq = false;
                    break;
                }
                meter.charge(awords(x.len()).saturating_mul(COST_EQUAL_WORD))?;
                if x != y {
                    eq = false;
                    break;
                }
            }
            (None, None) => {
                // Both are cells; splits cannot fail.
                let (Some((ph, pt)), Some((qh, qt))) = (p.as_cell(), q.as_cell()) else {
                    return Err(GrainTrap::TypeMismatch);
                };
                stack.push((pt.clone(), qt.clone()));
                stack.push((ph.clone(), qh.clone()));
            }
            _ => {
                eq = false;
                break;
            }
        }
    }
    // Loobean constants carry no allocation charge (spec §6).
    Ok(if eq {
        Noun::atom_u64(0)
    } else {
        Noun::atom_u64(1)
    })
}
