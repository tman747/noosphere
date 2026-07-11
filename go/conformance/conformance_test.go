package conformance

import (
	"strings"
	"testing"
)

// TestAllVectors runs every understood vector file and requires zero
// failures. Weft checker-semantics cases are the only permitted skips
// (the recorded seam); every other family must fully pass.
func TestAllVectors(t *testing.T) {
	root, err := FindVectorRoot(".")
	if err != nil {
		t.Fatalf("vector root: %v", err)
	}
	files, err := VectorFiles(root)
	if err != nil {
		t.Fatalf("list vectors: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}
	ran := 0
	for _, f := range files {
		rep, err := RunFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if rep == nil {
			continue // family outside this client's scope (crypto, da)
		}
		ran++
		pass, fail, skipN := rep.Counts()
		t.Logf("%-55s pass=%d fail=%d skip=%d", rep.File, pass, fail, skipN)
		for _, c := range rep.Cases {
			if c.Status == Fail {
				t.Errorf("%s / %s: %s", rep.File, c.Name, c.Detail)
			}
			if c.Status == Skip && !strings.Contains(rep.Schema, "weft") {
				t.Errorf("%s / %s: unexpected skip outside the weft seam", rep.File, c.Name)
			}
		}
	}
	if ran == 0 {
		t.Fatal("no understood vector files ran")
	}
}

// TestVectorCorpusShape pins the frozen per-family case counts this
// client certifies. A change here means the frozen inputs moved.
func TestVectorCorpusShape(t *testing.T) {
	root, err := FindVectorRoot(".")
	if err != nil {
		t.Fatalf("vector root: %v", err)
	}
	want := map[string]int{
		"codec/codec-v1.json":                     60,
		"lumen/lumen-smt-v1.json":                 6,
		"lumen/lumen-ids-v1.json":                 7,
		"lumen/lumen-tx-v1.json":                  16,
		"braid/braid-header-v1.json":              9,
		"braid/braid-header-validation-v1.json":   6,
		"braid/braid-proposal-commitment-v1.json": 5,
		"braid/braid-fork-choice-v1.json":         7,
		"braid/braid-body-v1.json":                6,
		"ground/ground-ticket-v1.json":            22,
		"ground/pulse-retarget-v1.json":           22,
		"witness/witness-vote-v1.json":            6,
		"witness/witness-certificate-v1.json":     11,
		"witness/witness-membership-v1.json":      5,
		"witness/witness-threshold-v1.json":       19,
		"witness/witness-bond-v1.json":            7,
		"witness/witness-slashing-v1.json":        9,
		"witness/witness-beacon-v1.json":          7,
	}
	for rel, n := range want {
		rep, err := RunFile(root + "/" + rel)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if rep == nil {
			t.Fatalf("%s: schema not understood", rel)
		}
		if len(rep.Cases) != n {
			t.Errorf("%s: %d cases, want %d", rel, len(rep.Cases), n)
		}
	}
}
