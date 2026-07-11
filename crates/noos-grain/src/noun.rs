//! Noun representation: compact minimal-LE atoms and structurally shared
//! cells with cached depth. No floats anywhere; all algorithms that scale
//! with depth are iterative (spec §13).

use std::rc::Rc;

use crate::{GrainTrap, MAX_CELL_DEPTH};

#[derive(Debug)]
pub(crate) enum NounRepr {
    /// Minimal little-endian bytes: empty for zero; otherwise the last byte
    /// (most significant) is nonzero.
    Atom(Box<[u8]>),
    Cell {
        head: Noun,
        tail: Noun,
        depth: u32,
    },
}

/// An unsigned atom or an ordered cell `[head tail]`.
///
/// Cheap to clone (reference-counted, structurally shared). The inner
/// `Option` is `Some` for every live noun; it exists only so `Drop` can
/// detach children without recursion.
#[derive(Debug, Clone)]
pub struct Noun(Option<Rc<NounRepr>>);

impl Noun {
    #[inline]
    pub(crate) fn from_repr(repr: NounRepr) -> Noun {
        Noun(Some(Rc::new(repr)))
    }

    #[inline]
    pub(crate) fn repr(&self) -> &NounRepr {
        match &self.0 {
            Some(r) => r,
            // A live noun is always Some; None exists only mid-drop.
            None => unreachable!("noun accessed during teardown"),
        }
    }

    /// Atom from raw little-endian bytes; trailing (most-significant) zero
    /// bytes are trimmed so the stored form is always minimal.
    pub fn atom_from_le_bytes(bytes: &[u8]) -> Noun {
        let end = bytes
            .iter()
            .rposition(|b| *b != 0)
            .map_or(0, |i| i.saturating_add(1));
        Noun::from_repr(NounRepr::Atom(bytes[..end].to_vec().into_boxed_slice()))
    }

    /// Atom from already-minimal bytes (internal fast path; caller upholds
    /// minimality).
    #[inline]
    pub(crate) fn atom_from_minimal(bytes: Vec<u8>) -> Noun {
        debug_assert!(bytes.last() != Some(&0));
        Noun::from_repr(NounRepr::Atom(bytes.into_boxed_slice()))
    }

    /// Small-atom convenience.
    pub fn atom_u64(v: u64) -> Noun {
        Noun::atom_from_le_bytes(&v.to_le_bytes())
    }

    /// Construct a cell, enforcing the frozen depth bound
    /// (`NOUN_OVERSIZED` on violation).
    pub fn cell(head: Noun, tail: Noun) -> Result<Noun, GrainTrap> {
        let d = head.depth().max(tail.depth());
        if d >= MAX_CELL_DEPTH {
            return Err(GrainTrap::NounOversized);
        }
        // d < MAX_CELL_DEPTH <= u32::MAX, so d + 1 cannot overflow.
        let depth = d.saturating_add(1);
        Ok(Noun::from_repr(NounRepr::Cell { head, tail, depth }))
    }

    /// `0` for atoms; `1 + max(child depths)` for cells.
    #[inline]
    pub fn depth(&self) -> u32 {
        match self.repr() {
            NounRepr::Atom(_) => 0,
            NounRepr::Cell { depth, .. } => *depth,
        }
    }

    #[inline]
    pub fn is_cell(&self) -> bool {
        matches!(self.repr(), NounRepr::Cell { .. })
    }

    #[inline]
    pub fn is_atom(&self) -> bool {
        !self.is_cell()
    }

    /// Minimal little-endian bytes, or `None` for a cell.
    #[inline]
    pub fn as_atom(&self) -> Option<&[u8]> {
        match self.repr() {
            NounRepr::Atom(b) => Some(b),
            NounRepr::Cell { .. } => None,
        }
    }

    /// Borrowed `(head, tail)`, or `None` for an atom.
    #[inline]
    pub fn as_cell(&self) -> Option<(&Noun, &Noun)> {
        match self.repr() {
            NounRepr::Atom(_) => None,
            NounRepr::Cell { head, tail, .. } => Some((head, tail)),
        }
    }

    /// Uncharged structural equality (host-side; the *metered* comparison of
    /// opcode 5 lives in `eval` with its frozen charge schedule).
    pub fn structural_eq(&self, other: &Noun) -> bool {
        let mut stack: Vec<(Noun, Noun)> = vec![(self.clone(), other.clone())];
        while let Some((p, q)) = stack.pop() {
            match (p.repr(), q.repr()) {
                (NounRepr::Atom(a), NounRepr::Atom(b)) => {
                    if a != b {
                        return false;
                    }
                }
                (
                    NounRepr::Cell {
                        head: ph, tail: pt, ..
                    },
                    NounRepr::Cell {
                        head: qh, tail: qt, ..
                    },
                ) => {
                    stack.push((pt.clone(), qt.clone()));
                    stack.push((ph.clone(), qh.clone()));
                }
                _ => return false,
            }
        }
        true
    }
}

impl PartialEq for Noun {
    fn eq(&self, other: &Noun) -> bool {
        self.structural_eq(other)
    }
}

impl Eq for Noun {}

/// Iterative teardown: a uniquely-owned deep noun must not recurse on drop
/// (spec §13 obligation 1).
impl Drop for Noun {
    fn drop(&mut self) {
        let Some(rc) = self.0.take() else { return };
        // Fast path: shared or an atom — Rc handles it without recursion.
        if Rc::strong_count(&rc) > 1 || matches!(*rc, NounRepr::Atom(_)) {
            return;
        }
        let mut stack: Vec<Rc<NounRepr>> = vec![rc];
        while let Some(rc) = stack.pop() {
            if let Ok(NounRepr::Cell {
                mut head, mut tail, ..
            }) = Rc::try_unwrap(rc)
            {
                if let Some(h) = head.0.take() {
                    stack.push(h);
                }
                if let Some(t) = tail.0.take() {
                    stack.push(t);
                }
            }
        }
    }
}
