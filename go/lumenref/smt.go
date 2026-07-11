package lumenref

import (
	"bytes"
	"slices"
)

// Depth-256 sparse Merkle tree per protocol/schemas/lumen-v1.md §2.
//
// Keys are exactly 32 bytes; path bit d (depth from root, 0..256) is
// (key[d/8] >> (7 - d%8)) & 1, 0 = left. Leaf hash is
// H("NOOS/SMT/LEAF/V1" || key || value); node hash is
// H("NOOS/SMT/NODE/V1" || left || right); empty roots are recursively
// derived: E[0] = H(leaf_ctx), E[h] = H(node_ctx || E[h-1] || E[h-1]).
// The root is a pure function of the key→value map.

const (
	smtLeafCtx = "NOOS/SMT/LEAF/V1"
	smtNodeCtx = "NOOS/SMT/NODE/V1"
	// SMTDepth is the frozen tree depth.
	SMTDepth = 256
)

var smtEmpty [SMTDepth + 1][32]byte

func init() {
	smtEmpty[0] = DomainHash(smtLeafCtx)
	for h := 1; h <= SMTDepth; h++ {
		smtEmpty[h] = DomainHash(smtNodeCtx, smtEmpty[h-1][:], smtEmpty[h-1][:])
	}
}

// SMTEmptyRoot returns E[h], the root of an empty subtree of height h.
// The empty tree root is SMTEmptyRoot(256).
func SMTEmptyRoot(h int) [32]byte { return smtEmpty[h] }

// SMT is an in-memory depth-256 sparse Merkle tree. The zero value is
// ready to use.
type SMT struct {
	leaves map[[32]byte][]byte
}

// Put inserts or replaces the value under key. A duplicate-key update
// replaces the value.
func (t *SMT) Put(key [32]byte, value []byte) {
	if t.leaves == nil {
		t.leaves = make(map[[32]byte][]byte)
	}
	v := make([]byte, len(value))
	copy(v, value)
	t.leaves[key] = v
}

// Delete removes the key; deleting restores the exact prior root.
func (t *SMT) Delete(key [32]byte) {
	delete(t.leaves, key)
}

// Len is the number of leaves.
func (t *SMT) Len() int { return len(t.leaves) }

// Root computes the tree root. Insertion order never affects the result.
func (t *SMT) Root() [32]byte {
	keys := make([][32]byte, 0, len(t.leaves))
	for k := range t.leaves {
		keys = append(keys, k)
	}
	sortKeys(keys)
	return t.subtree(keys, 0)
}

// pathBit is the frozen key-to-path law.
func pathBit(key [32]byte, depth int) int {
	return int(key[depth/8]>>(7-depth%8)) & 1
}

// subtree builds the root of the subtree at the given depth over the sorted
// key slice (lexicographic key order equals MSB-first path order, so a
// sorted slice splits with one binary search per level).
func (t *SMT) subtree(keys [][32]byte, depth int) [32]byte {
	if len(keys) == 0 {
		return smtEmpty[SMTDepth-depth]
	}
	if depth == SMTDepth {
		k := keys[0]
		return DomainHash(smtLeafCtx, k[:], t.leaves[k])
	}
	split := len(keys)
	for i, k := range keys {
		if pathBit(k, depth) == 1 {
			split = i
			break
		}
	}
	left := t.subtree(keys[:split], depth+1)
	right := t.subtree(keys[split:], depth+1)
	return DomainHash(smtNodeCtx, left[:], right[:])
}

func sortKeys(keys [][32]byte) {
	slices.SortFunc(keys, func(a, b [32]byte) int {
		return bytes.Compare(a[:], b[:])
	})
}
