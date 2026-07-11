//! Canonical noun byte encoding (spec §4): self-contained, self-delimiting,
//! prefix form. `atom := 0x00 len:u32-LE payload[len]` (minimal LE payload);
//! `cell := 0x01 head tail`. Decode is iterative, unmetered, and rejects per
//! the ordered law of spec §4.1.

use crate::noun::{Noun, NounRepr};
use crate::{GrainTrap, MAX_ATOM_BYTES, MAX_FORMULA_BYTES, MAX_SUBJECT_BYTES};

const TAG_ATOM: u8 = 0x00;
const TAG_CELL: u8 = 0x01;

/// Canonical encoding. Never fails; `decode(encode(n)) == n`.
pub fn encode_noun(n: &Noun) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack: Vec<&Noun> = vec![n];
    while let Some(cur) = stack.pop() {
        match cur.repr() {
            NounRepr::Atom(b) => {
                out.push(TAG_ATOM);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            NounRepr::Cell { head, tail, .. } => {
                out.push(TAG_CELL);
                stack.push(tail);
                stack.push(head);
            }
        }
    }
    out
}

/// Decode a formula: total length bound `MAX_FORMULA_BYTES`, oversize trap
/// `FORMULA_OVERSIZED`.
pub fn decode_formula(bytes: &[u8]) -> Result<Noun, GrainTrap> {
    decode(bytes, MAX_FORMULA_BYTES, GrainTrap::FormulaOversized)
}

/// Decode a subject: total length bound `MAX_SUBJECT_BYTES`, oversize trap
/// `SUBJECT_OVERSIZED`.
pub fn decode_subject(bytes: &[u8]) -> Result<Noun, GrainTrap> {
    decode(bytes, MAX_SUBJECT_BYTES, GrainTrap::SubjectOversized)
}

/// Ordered rejection law (spec §4.1). Iterative: frame stack, no recursion.
fn decode(bytes: &[u8], max_bytes: usize, oversize: GrainTrap) -> Result<Noun, GrainTrap> {
    if bytes.len() > max_bytes {
        return Err(oversize);
    }
    if bytes.is_empty() {
        return Err(GrainTrap::MalformedBytes);
    }

    let mut pos: usize = 0;
    // Each frame is a cell awaiting children: None = waiting for head,
    // Some(head) = waiting for tail.
    let mut frames: Vec<Option<Noun>> = Vec::new();

    loop {
        let tag = *bytes.get(pos).ok_or(GrainTrap::MalformedBytes)?;
        pos = pos.saturating_add(1);
        let mut node: Noun = match tag {
            TAG_ATOM => {
                let end = pos.checked_add(4).ok_or(GrainTrap::MalformedBytes)?;
                let len_bytes = bytes.get(pos..end).ok_or(GrainTrap::MalformedBytes)?;
                pos = end;
                let len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                // Atom bound BEFORE the remaining-input check; no allocation
                // may precede either check.
                if len > MAX_ATOM_BYTES {
                    return Err(GrainTrap::NounOversized);
                }
                let end = pos.checked_add(len).ok_or(GrainTrap::MalformedBytes)?;
                let payload = bytes.get(pos..end).ok_or(GrainTrap::MalformedBytes)?;
                pos = end;
                if payload.last() == Some(&0x00) {
                    return Err(GrainTrap::MalformedBytes);
                }
                Noun::atom_from_minimal(payload.to_vec())
            }
            TAG_CELL => {
                frames.push(None);
                continue;
            }
            _ => return Err(GrainTrap::MalformedBytes),
        };

        // Resolve the completed node upward through pending cell frames.
        loop {
            match frames.last_mut() {
                None => {
                    if pos != bytes.len() {
                        return Err(GrainTrap::MalformedBytes);
                    }
                    return Ok(node);
                }
                Some(slot) => match slot.take() {
                    None => {
                        *slot = Some(node);
                        break; // parse the tail next
                    }
                    Some(head) => {
                        frames.pop();
                        // Depth bound: NOUN_OVERSIZED via Noun::cell.
                        node = Noun::cell(head, node)?;
                    }
                },
            }
        }
    }
}
