package braidref

import (
	"math/big"
	"testing"
)

// Fork-choice lexicographic precedence (plan §6.4): each earlier tuple
// component strictly dominates all later ones.
func TestForkChoicePrecedence(t *testing.T) {
	base := ForkTuple{FinalizedEpoch: 1, JustifiedEpoch: 1}
	higherFin := base
	higherFin.FinalizedEpoch = 2
	maxWork := base
	for i := range maxWork.WorkLE {
		maxWork.WorkLE[i] = 0xff
	}
	if Compare(higherFin, maxWork) <= 0 {
		t.Fatal("finalized checkpoint must dominate work")
	}
	smallHash := base
	bigHash := base
	bigHash.BlockHash[31] = 1
	if Compare(smallHash, bigHash) <= 0 {
		t.Fatal("smaller hash must win a full tie")
	}
	if Compare(base, base) != 0 {
		t.Fatal("identical tuples must compare equal")
	}
}

// Exact threshold law spot checks (witness-v1.md §3).
func TestJustificationThreshold(t *testing.T) {
	for _, tc := range []struct{ w, q int64 }{
		{0, 1}, {1, 1}, {2, 2}, {3, 3}, {100, 67}, {99, 67},
	} {
		if got := JustificationThreshold(big.NewInt(tc.w)); got.Int64() != tc.q {
			t.Fatalf("W=%d: Q=%d, want %d", tc.w, got, tc.q)
		}
	}
}

// Pulse short circuits sit exactly at the frozen boundaries: q = 255
// computes, q = 256 clamps to T_max; q = -256 computes, q = -257 clamps
// to T_min (pulse-exp2-v1.md §3.3).
func TestPulseShortCircuitBoundaries(t *testing.T) {
	one := big.NewInt(1)
	// n = q * 3600 exactly, h-h_a chosen so t-t_a = n + 6.
	at := func(q int64) *big.Int {
		n := q * 3600
		return PulseTargetV1(one, n+6, 0, 2, 1)
	}
	if at(256).Cmp(TMax()) != 0 {
		t.Fatal("q=256 must clamp to T_max")
	}
	if got := at(255); got.Cmp(TMax()) >= 0 {
		t.Fatal("q=255 must compute below T_max for T_a=1")
	}
	if at(-257).Cmp(one) != 0 {
		t.Fatal("q=-257 must clamp to T_min")
	}
}

// Median-time-past uses the median of the last 11 timestamps.
func TestMedianTimePast(t *testing.T) {
	ts := []uint64{5, 1, 9, 3, 7, 2, 8, 4, 6, 10, 11}
	if got := MedianTimePastMS(ts); got != 6 {
		t.Fatalf("mtp %d, want 6", got)
	}
	if got := MedianTimePastMS([]uint64{42}); got != 42 {
		t.Fatalf("single-ancestor mtp %d, want 42", got)
	}
}

// Header-chain linkage law: parent hash, height, and slot monotonicity.
func TestValidateChainLink(t *testing.T) {
	parent := &BlockHeaderV1{Height: 5, Slot: 10, GroundProfileID: 1}
	child := &BlockHeaderV1{Height: 6, Slot: 10, GroundProfileID: 1}
	child.ParentHash = parent.BlockHash()
	if err := ValidateChainLink(parent, child); err != nil {
		t.Fatalf("valid link rejected: %v", err)
	}
	badHash := *child
	badHash.ParentHash[0] ^= 1
	if ValidateChainLink(parent, &badHash) == nil {
		t.Fatal("wrong parent hash accepted")
	}
	badHeight := *child
	badHeight.Height = 7
	if ValidateChainLink(parent, &badHeight) == nil {
		t.Fatal("height gap accepted")
	}
	badSlot := *child
	badSlot.Slot = 9
	if ValidateChainLink(parent, &badSlot) == nil {
		t.Fatal("slot regression accepted")
	}
}
