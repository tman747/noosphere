package grainref

import "encoding/binary"

// Canonical byte encoding (spec §4):
//
//	noun  := atom | cell
//	atom  := 0x00  len:u32-LE  payload[len]   -- payload LE, minimal
//	cell  := 0x01  noun(head)  noun(tail)
//
// A top-level decode must consume the entire input. Decoding is not metered
// and does not count against the arena; on a decode trap the evaluation
// charge is 0 (spec §4.1).

// DecodeFormula decodes formula bytes under (MaxFormulaBytes,
// TrapFormulaOversized). Spec §4.1.
func DecodeFormula(b []byte) (*Noun, Trap) {
	return decode(b, MaxFormulaBytes, TrapFormulaOversized)
}

// DecodeSubject decodes subject bytes under (MaxSubjectBytes,
// TrapSubjectOversized). Spec §4.1.
func DecodeSubject(b []byte) (*Noun, Trap) {
	return decode(b, MaxSubjectBytes, TrapSubjectOversized)
}

// decode parses one noun in prefix order, iteratively (no host recursion
// proportional to depth — spec §13.1). The ordered §4.1 rejection law:
// oversize input, empty input, bad tag, truncation, atom length bound
// (checked BEFORE the remaining-input check), nonminimal payload, cell
// depth bound, trailing bytes.
//
// Atom payloads alias the input slice; callers must not mutate accepted
// input afterwards.
func decode(b []byte, maxBytes uint64, oversize Trap) (*Noun, Trap) {
	if uint64(len(b)) > maxBytes {
		return nil, oversize
	}
	if len(b) == 0 {
		return nil, TrapMalformedBytes
	}
	// pending[i] is a cell whose head has been parsed iff heads[i] != nil.
	var heads []*Noun
	pos := 0
	for {
		// Parse exactly one noun starting at pos.
		var n *Noun
		for {
			if pos >= len(b) {
				return nil, TrapMalformedBytes // tag byte absent
			}
			tag := b[pos]
			pos++
			if tag == 0x01 {
				heads = append(heads, nil) // open cell, need head then tail
				continue
			}
			if tag != 0x00 {
				return nil, TrapMalformedBytes // bad tag
			}
			if pos+4 > len(b) {
				return nil, TrapMalformedBytes // 4-byte length absent
			}
			l := binary.LittleEndian.Uint32(b[pos:])
			pos += 4
			if uint64(l) > MaxAtomBytes {
				return nil, TrapNounOversized // before the remaining-input check
			}
			ln := int(l)
			if len(b)-pos < ln {
				return nil, TrapMalformedBytes // payload truncated
			}
			if ln > 0 && b[pos+ln-1] == 0x00 {
				return nil, TrapMalformedBytes // nonminimal atom
			}
			n = newAtom(b[pos : pos+ln])
			pos += ln
			break
		}
		// Attach the completed noun n upward through finished cells.
		for len(heads) > 0 {
			top := len(heads) - 1
			if heads[top] == nil {
				heads[top] = n // n is the head; the tail parse comes next
				n = nil
				break
			}
			h := heads[top]
			heads = heads[:top]
			d := h.depth
			if n.depth > d {
				d = n.depth
			}
			if d+1 > MaxCellDepth {
				return nil, TrapNounOversized
			}
			n = &Noun{head: h, tail: n, depth: d + 1}
		}
		if n != nil && len(heads) == 0 {
			if pos != len(b) {
				return nil, TrapMalformedBytes // trailing bytes
			}
			return n, TrapNone
		}
	}
}

// Encode produces the canonical bytes of a noun, iteratively. Encoding never
// fails; encode(decode(b)) == b for every accepted b (spec §4.1).
func Encode(n *Noun) []byte {
	out := make([]byte, 0, 64)
	stack := []*Noun{n}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.IsCell() {
			out = append(out, 0x01)
			stack = append(stack, cur.tail, cur.head)
			continue
		}
		out = append(out, 0x00)
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(cur.bytes)))
		out = append(out, l[:]...)
		out = append(out, cur.bytes...)
	}
	return out
}
