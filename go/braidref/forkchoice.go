package braidref

import "bytes"

// Fork choice per ch01 M-CLOCK / plan §6.4 (header-body.md "Fork-choice
// tuple"): lexicographic over (finalized checkpoint, justified checkpoint,
// cumulative normalized G+L, inverse block hash). Finalized checkpoints
// cannot be reverted by work; on a full tie the numerically SMALLER hash
// (byte-lexicographic big-endian) wins.

// ForkTuple is one branch head's comparison tuple. Work is the cumulative
// normalized G+L as a 32-byte little-endian unsigned integer.
type ForkTuple struct {
	FinalizedEpoch uint64
	JustifiedEpoch uint64
	WorkLE         [32]byte
	BlockHash      [32]byte
}

// Compare returns >0 if a wins, <0 if b wins, 0 if the tuples are fully
// identical.
func Compare(a, b ForkTuple) int {
	if a.FinalizedEpoch != b.FinalizedEpoch {
		if a.FinalizedEpoch > b.FinalizedEpoch {
			return 1
		}
		return -1
	}
	if a.JustifiedEpoch != b.JustifiedEpoch {
		if a.JustifiedEpoch > b.JustifiedEpoch {
			return 1
		}
		return -1
	}
	if c := compareU256LE(a.WorkLE, b.WorkLE); c != 0 {
		return c
	}
	// inverse hash: the smaller hash wins
	return -bytes.Compare(a.BlockHash[:], b.BlockHash[:])
}

// compareU256LE compares two little-endian 256-bit integers.
func compareU256LE(a, b [32]byte) int {
	for i := 31; i >= 0; i-- {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}
