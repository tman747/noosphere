package grainref

// Noun is an atom (arbitrary-size unsigned integer, canonical minimal
// little-endian bytes) or a cell (ordered pair of nouns). Spec §3.
//
// Nouns are immutable after construction and structurally shared; sharing is
// an implementation technique invisible to the charge schedule (spec §13.5).
type Noun struct {
	head  *Noun  // nil for an atom
	tail  *Noun  // nil for an atom
	bytes []byte // minimal LE payload; empty/nil is the atom 0
	depth uint32 // 0 for atoms; 1 + max(child depths) for cells
}

// IsCell reports whether n is a cell.
func (n *Noun) IsCell() bool { return n.head != nil }

// Head returns the head of a cell, or nil for an atom.
func (n *Noun) Head() *Noun { return n.head }

// Tail returns the tail of a cell, or nil for an atom.
func (n *Noun) Tail() *Noun { return n.tail }

// AtomBytes returns the minimal little-endian payload of an atom (empty for
// the atom 0), or nil for a cell.
func (n *Noun) AtomBytes() []byte {
	if n.IsCell() {
		return nil
	}
	return n.bytes
}

// Depth returns the cell depth of n (0 for atoms). Spec §3.
func (n *Noun) Depth() uint32 { return n.depth }

// Shared canonical constant atoms produced by opcodes 3 and 5 (spec §6):
// producing them charges no allocation.
var (
	atomZero = &Noun{}
	atomOne  = &Noun{bytes: []byte{1}}
)

// newAtom wraps minimal little-endian payload bytes as an atom without
// copying. Callers guarantee minimality (no trailing zero byte).
func newAtom(minimal []byte) *Noun {
	if len(minimal) == 0 {
		return atomZero
	}
	return &Noun{bytes: minimal}
}

// newCellUnchecked pairs two nouns without limit checks; the caller has
// already run the §6 allocation sequence or the §4.1 decode depth check.
func newCellUnchecked(h, t *Noun) *Noun {
	d := h.depth
	if t.depth > d {
		d = t.depth
	}
	return &Noun{head: h, tail: t, depth: d + 1}
}
