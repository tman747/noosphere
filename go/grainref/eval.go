package grainref

import (
	stdbytes "bytes"
	"math/bits"
)

// Eval evaluates formula against subject under the meter (spec §§1, 6–11).
// It returns (result, TrapNone) or (nil, trap). The reported charge is
// m.Spent() at return in both cases.
//
// The machine is fully iterative: an explicit continuation stack carries
// pending work, so host call-stack use never grows with evaluation depth
// (spec §13.1). Tail positions (final sub-evaluations of ops 2, 6, 7, 8, 9,
// 11 and cons) replace the current task without pushing a continuation.
func Eval(version uint32, subject, formula *Noun, m *Meter) (*Noun, Trap) {
	if version != GrainVersion {
		return nil, TrapUnknownVersion // charge 0, before any other observation
	}
	conts := make([]cont, 0, 32)
	s, f := subject, formula
	var v *Noun

EvalLoop:
	for {
		// ---- §8 dispatch of (s, f) ----
		// 1. atom formula
		if !f.IsCell() {
			return nil, TrapTypeMismatch // no charge
		}
		head, arg := f.head, f.tail

		// 3. cons composition: head is a cell
		if head.IsCell() {
			if t := m.charge(costCons); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kConsFh, sub: s, f: arg})
			f = head
			continue EvalLoop
		}

		// 4. opcode range
		hb := head.bytes
		if len(hb) > 1 || (len(hb) == 1 && hb[0] > 11) {
			return nil, TrapUnknownOpcode // no charge
		}
		var op byte
		if len(hb) == 1 {
			op = hb[0]
		}

		// 5. shape validation (no charge), 6. dispatch charge, 7. reduction
		switch op {
		case 0: // slot
			if arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			if len(arg.bytes) == 0 {
				return nil, TrapInvalidAxis
			}
			if t := chargeSlot(m, arg); t != TrapNone {
				return nil, t
			}
			r, t := walk(s, arg)
			if t != TrapNone {
				return nil, t
			}
			v = r // shared, no allocation

		case 1: // quote
			if t := m.charge(costQuote); t != TrapNone {
				return nil, t
			}
			v = arg // shared, no allocation

		case 2: // apply: *[s [2 b c]] = *[*[s b] *[s c]]
			if !arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			if t := m.charge(costApply); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kApplyB, sub: s, f: arg.tail})
			f = arg.head
			continue EvalLoop

		case 3: // is-cell
			if t := m.charge(costIsCell); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kIsCell})
			f = arg
			continue EvalLoop

		case 4: // inc — no dispatch charge
			conts = append(conts, cont{kind: kInc})
			f = arg
			continue EvalLoop

		case 5: // equal — no dispatch charge
			if !arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			conts = append(conts, cont{kind: kEqualB, sub: s, f: arg.tail})
			f = arg.head
			continue EvalLoop

		case 6: // if: arg must be [b [c d]]
			if !arg.IsCell() || !arg.tail.IsCell() {
				return nil, TrapTypeMismatch
			}
			if t := m.charge(costIf); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kIf, sub: s, f: arg.tail.head, g: arg.tail.tail})
			f = arg.head
			continue EvalLoop

		case 7: // compose
			if !arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			if t := m.charge(costCompose); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kCompose, f: arg.tail})
			f = arg.head
			continue EvalLoop

		case 8: // push
			if !arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			if t := m.charge(costPush); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kPush, sub: s, f: arg.tail})
			f = arg.head
			continue EvalLoop

		case 9: // arm: arg [b c], b atom nonzero
			if !arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			if arg.head.IsCell() {
				return nil, TrapTypeMismatch
			}
			if len(arg.head.bytes) == 0 {
				return nil, TrapInvalidAxis
			}
			if t := m.charge(costArm); t != TrapNone {
				return nil, t
			}
			conts = append(conts, cont{kind: kArm, ax: arg.head})
			f = arg.tail
			continue EvalLoop

		case 10: // edit: arg [[b c] d], b atom nonzero — no dispatch charge
			if !arg.IsCell() || !arg.head.IsCell() {
				return nil, TrapTypeMismatch
			}
			if arg.head.head.IsCell() {
				return nil, TrapTypeMismatch
			}
			if len(arg.head.head.bytes) == 0 {
				return nil, TrapInvalidAxis
			}
			conts = append(conts, cont{kind: kEditC, sub: s, ax: arg.head.head, f: arg.tail})
			f = arg.head.tail // evaluate c first, then d
			continue EvalLoop

		case 11: // hint: [11 h f] — h never evaluated, COST_HINT = 0
			if !arg.IsCell() {
				return nil, TrapTypeMismatch
			}
			f = arg.tail // tail position
			continue EvalLoop
		}

		// ---- return v through the continuation stack ----
	ReturnLoop:
		for {
			if len(conts) == 0 {
				return v, TrapNone
			}
			c := conts[len(conts)-1]
			conts = conts[:len(conts)-1]
			switch c.kind {
			case kConsFh: // have *[s fh]; evaluate ft
				conts = append(conts, cont{kind: kConsFt, x: v})
				s, f = c.sub, c.f
				continue EvalLoop
			case kConsFt: // have both halves; allocate the pair
				nc, t := allocCell(m, c.x, v)
				if t != TrapNone {
					return nil, t
				}
				v = nc
				continue ReturnLoop
			case kApplyB: // have the new subject; evaluate c
				conts = append(conts, cont{kind: kApplyC, x: v})
				s, f = c.sub, c.f
				continue EvalLoop
			case kApplyC: // have the new formula; tail-evaluate it
				s, f = c.x, v
				continue EvalLoop
			case kIsCell:
				if v.IsCell() {
					v = atomZero
				} else {
					v = atomOne
				}
				continue ReturnLoop
			case kInc:
				nv, t := incComplete(m, v)
				if t != TrapNone {
					return nil, t
				}
				v = nv
				continue ReturnLoop
			case kEqualB:
				conts = append(conts, cont{kind: kEqualC, x: v})
				s, f = c.sub, c.f
				continue EvalLoop
			case kEqualC:
				nv, t := equalComplete(m, c.x, v)
				if t != TrapNone {
					return nil, t
				}
				v = nv
				continue ReturnLoop
			case kIf: // v is the condition
				if v.IsCell() || len(v.bytes) > 1 {
					return nil, TrapTypeMismatch
				}
				if len(v.bytes) == 0 {
					f = c.f // atom 0: then-branch
				} else if v.bytes[0] == 1 {
					f = c.g // atom 1: else-branch
				} else {
					return nil, TrapTypeMismatch
				}
				s = c.sub
				continue EvalLoop
			case kCompose: // v is the new subject
				s, f = v, c.f
				continue EvalLoop
			case kPush: // v is the pushed value; allocate [v s]
				nc, t := allocCell(m, v, c.sub)
				if t != TrapNone {
					return nil, t
				}
				s, f = nc, c.f
				continue EvalLoop
			case kArm: // v is the core; slot charge, walk, tail-evaluate arm
				if t := chargeSlot(m, c.ax); t != TrapNone {
					return nil, t
				}
				af, t := walk(v, c.ax)
				if t != TrapNone {
					return nil, t
				}
				s, f = v, af
				continue EvalLoop
			case kEditC: // v is the replacement; evaluate d
				conts = append(conts, cont{kind: kEditD, ax: c.ax, x: v})
				s, f = c.sub, c.f
				continue EvalLoop
			case kEditD: // v is the target tree
				nv, t := editComplete(m, c.ax, c.x, v)
				if t != TrapNone {
					return nil, t
				}
				v = nv
				continue ReturnLoop
			}
		}
	}
}

type contKind uint8

const (
	kConsFh contKind = iota
	kConsFt
	kApplyB
	kApplyC
	kIsCell
	kInc
	kEqualB
	kEqualC
	kIf
	kCompose
	kPush
	kArm
	kEditC
	kEditD
)

// cont is one pending continuation frame of the iterative machine.
type cont struct {
	kind contKind
	sub  *Noun // saved subject
	x    *Noun // first computed value
	f    *Noun // pending sub-formula
	g    *Noun // second pending sub-formula (op 6 else-branch)
	ax   *Noun // axis atom (ops 9, 10)
}

// bitsOf returns the bit length of a nonzero atom (spec §7).
func bitsOf(a *Noun) uint64 {
	n := len(a.bytes)
	return uint64(n-1)*8 + uint64(bits.Len8(a.bytes[n-1]))
}

// chargeSlot charges the full slot cost for an axis before any walk:
// COST_SLOT_BASE + (bits(axis)-1) * COST_SLOT_STEP (spec §7).
func chargeSlot(m *Meter, ax *Noun) Trap {
	return m.charge(costSlotBase + (bitsOf(ax)-1)*costSlotStep)
}

// walk applies the §7 axis walk to n. The axis is a nonzero atom; the
// caller has already charged the slot cost where one is due.
func walk(n *Noun, ax *Noun) (*Noun, Trap) {
	for i := int64(bitsOf(ax)) - 2; i >= 0; i-- {
		if !n.IsCell() {
			return nil, TrapInvalidAxis
		}
		if ax.bytes[i>>3]>>(uint(i)&7)&1 == 0 {
			n = n.head
		} else {
			n = n.tail
		}
	}
	return n, TrapNone
}

// allocCell runs the §6 allocation sequence for one cell: charge 3 steps,
// add 3 arena words, check the depth bound, construct.
func allocCell(m *Meter, h, t *Noun) (*Noun, Trap) {
	if tr := m.charge(costCellAlloc); tr != TrapNone {
		return nil, tr
	}
	if tr := m.arenaAdd(cellWords); tr != TrapNone {
		return nil, tr
	}
	d := h.depth
	if t.depth > d {
		d = t.depth
	}
	if d+1 > MaxCellDepth {
		return nil, TrapNounOversized
	}
	return &Noun{head: h, tail: t, depth: d + 1}, TrapNone
}

// awords is the word size of an atom payload length (spec §2).
func awords(n uint64) uint64 { return (n + 7) / WordBytes }

// incComplete is the op 4 completion (spec §9): type check, operand charge,
// increment, ATOM_BOUND check, then the atom allocation sequence.
func incComplete(m *Meter, a *Noun) (*Noun, Trap) {
	if a.IsCell() {
		return nil, TrapTypeMismatch
	}
	n := uint64(len(a.bytes))
	if t := m.charge(costIncBase + awords(n)*costIncWord); t != TrapNone {
		return nil, t
	}
	r := make([]byte, n, n+1)
	copy(r, a.bytes)
	carry := true
	for i := 0; i < len(r) && carry; i++ {
		r[i]++
		carry = r[i] == 0
	}
	if carry {
		r = append(r, 1)
	}
	rlen := uint64(len(r))
	if rlen > MaxAtomBytes {
		return nil, TrapAtomBound
	}
	// Allocation sequence for an atom of rlen bytes.
	w := 1 + awords(rlen)
	if t := m.charge(w); t != TrapNone {
		return nil, t
	}
	if t := m.arenaAdd(w); t != TrapNone {
		return nil, t
	}
	return newAtom(r), TrapNone
}

// equalComplete is the op 5 completion: base charge, then the frozen
// comparison walk (spec §9). Physical-identity shortcuts must not change
// the charge, so the walk always runs in full until a verdict.
func equalComplete(m *Meter, x, y *Noun) (*Noun, Trap) {
	if t := m.charge(costEqualBase); t != TrapNone {
		return nil, t
	}
	type pair struct{ p, q *Noun }
	stack := make([]pair, 1, 32)
	stack[0] = pair{x, y}
	for len(stack) > 0 {
		pr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if t := m.charge(costEqualNode); t != TrapNone {
			return nil, t
		}
		p, q := pr.p, pr.q
		pc, qc := p.IsCell(), q.IsCell()
		switch {
		case !pc && !qc:
			if len(p.bytes) != len(q.bytes) {
				return atomOne, TrapNone // no word charge
			}
			if t := m.charge(awords(uint64(len(p.bytes))) * costEqualWord); t != TrapNone {
				return nil, t
			}
			if !stdbytes.Equal(p.bytes, q.bytes) {
				return atomOne, TrapNone
			}
		case pc && qc:
			stack = append(stack, pair{p.tail, q.tail}, pair{p.head, q.head}) // heads compared first
		default:
			return atomOne, TrapNone
		}
	}
	return atomZero, TrapNone
}

// editComplete is the op 10 completion (spec §9), in frozen order:
// 1. charge COST_EDIT_BASE + L*COST_EDIT_STEP (L = bits(axis)-1);
// 2. walk t along the axis path (INVALID_AXIS on atom descent);
// 3. arena_add(3*L);
// 4. rebuild the spine bottom-up with a depth check per new cell.
// The completion charge pre-pays the per-level allocation steps; step 3
// adds only the words.
func editComplete(m *Meter, ax *Noun, v, t *Noun) (*Noun, Trap) {
	l := bitsOf(ax) - 1
	if tr := m.charge(costEditBase + l*costEditStep); tr != TrapNone {
		return nil, tr
	}
	if l == 0 {
		return v, TrapNone // #[1, v, t] = v: no walk, no allocation
	}
	// Walk, recording each level's direction bit and untouched sibling.
	dirs := make([]byte, 0, l)
	sibs := make([]*Noun, 0, l)
	cur := t
	for i := int64(l) - 1; i >= 0; i-- {
		if !cur.IsCell() {
			return nil, TrapInvalidAxis
		}
		b := ax.bytes[i>>3] >> (uint(i) & 7) & 1
		dirs = append(dirs, b)
		if b == 0 {
			sibs = append(sibs, cur.tail)
			cur = cur.head
		} else {
			sibs = append(sibs, cur.head)
			cur = cur.tail
		}
	}
	if tr := m.arenaAdd(3 * l); tr != TrapNone {
		return nil, tr
	}
	// Rebuild bottom-up: L new cells, each reusing the untouched sibling.
	res := v
	for j := len(dirs) - 1; j >= 0; j-- {
		var h, tl *Noun
		if dirs[j] == 0 {
			h, tl = res, sibs[j]
		} else {
			h, tl = sibs[j], res
		}
		d := h.depth
		if tl.depth > d {
			d = tl.depth
		}
		if d+1 > MaxCellDepth {
			return nil, TrapNounOversized
		}
		res = &Noun{head: h, tail: tl, depth: d + 1}
	}
	return res, TrapNone
}
