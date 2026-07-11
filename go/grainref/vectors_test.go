package grainref

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const vectorsDir = "../../protocol/vectors/grain"

type vecExpect struct {
	Kind     string  `json:"kind"`
	Noun     *string `json:"noun"`
	TrapCode *int    `json:"trap_code"`
	Charge   uint64  `json:"charge"`
}

type vecCase struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Bytes      string    `json:"bytes"`
	Subject    string    `json:"subject"`
	Formula    string    `json:"formula"`
	Erased     string    `json:"erased_formula"`
	Role       string    `json:"role"`
	Version    *uint32   `json:"version"`
	MeterLimit uint64    `json:"meter_limit"`
	ArenaLimit uint64    `json:"arena_limit"`
	Expect     vecExpect `json:"expect"`
}

type vecFile struct {
	Schema string    `json:"schema"`
	Cases  []vecCase `json:"cases"`
}

func loadVectors(t *testing.T, name, wantSchema string) []vecCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var f vecFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if f.Schema != wantSchema {
		t.Fatalf("%s: schema %q, want %q", name, f.Schema, wantSchema)
	}
	return f.Cases
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// evalOutcome is the observable conformance triple of one evaluation run
// under the §14 runner obligation order: version gate, decode subject,
// decode formula (decode traps report charge 0), eval.
type evalOutcome struct {
	trap   Trap // TrapNone for a value outcome
	noun   []byte
	charge uint64
}

func runEval(version uint32, subjectHex, formulaHex []byte, meterLimit, arenaLimit uint64) evalOutcome {
	m := NewMeter(meterLimit, arenaLimit)
	if version != GrainVersion {
		_, tr := Eval(version, nil, nil, m)
		return evalOutcome{trap: tr, charge: m.Spent()}
	}
	subj, tr := DecodeSubject(subjectHex)
	if tr != TrapNone {
		return evalOutcome{trap: tr, charge: 0}
	}
	form, tr := DecodeFormula(formulaHex)
	if tr != TrapNone {
		return evalOutcome{trap: tr, charge: 0}
	}
	res, tr := Eval(version, subj, form, m)
	if tr != TrapNone {
		return evalOutcome{trap: tr, charge: m.Spent()}
	}
	return evalOutcome{noun: Encode(res), charge: m.Spent()}
}

func checkOutcome(t *testing.T, c *vecCase, got evalOutcome) {
	t.Helper()
	switch c.Expect.Kind {
	case "value":
		if got.trap != TrapNone {
			t.Fatalf("%s: got trap %d, want value", c.Name, got.trap)
		}
		want := mustHex(t, *c.Expect.Noun)
		if !bytes.Equal(got.noun, want) {
			t.Fatalf("%s: noun %x, want %x", c.Name, got.noun, want)
		}
	case "trap":
		if got.trap == TrapNone {
			t.Fatalf("%s: got value %x, want trap %d", c.Name, got.noun, *c.Expect.TrapCode)
		}
		if int(got.trap) != *c.Expect.TrapCode {
			t.Fatalf("%s: trap %d, want %d", c.Name, got.trap, *c.Expect.TrapCode)
		}
	default:
		t.Fatalf("%s: unknown expect kind %q", c.Name, c.Expect.Kind)
	}
	if got.charge != c.Expect.Charge {
		t.Fatalf("%s: charge %d, want %d", c.Name, got.charge, c.Expect.Charge)
	}
}

func caseVersion(c *vecCase) uint32 {
	if c.Version != nil {
		return *c.Version
	}
	return GrainVersion
}

func TestEvalVectors(t *testing.T) {
	cases := loadVectors(t, "grain-eval-v1.json", "noos/grain/eval-v1")
	if len(cases) == 0 {
		t.Fatal("no eval cases")
	}
	for i := range cases {
		c := &cases[i]
		if c.Formula != c.Bytes {
			t.Fatalf("%s: formula != bytes", c.Name)
		}
		got := runEval(caseVersion(c), mustHex(t, c.Subject), mustHex(t, c.Formula), c.MeterLimit, c.ArenaLimit)
		checkOutcome(t, c, got)
	}
	t.Logf("eval vectors: %d cases", len(cases))
}

func TestNounBytesVectors(t *testing.T) {
	cases := loadVectors(t, "grain-noun-bytes-v1.json", "noos/grain/noun-bytes-v1")
	if len(cases) == 0 {
		t.Fatal("no noun-bytes cases")
	}
	for i := range cases {
		c := &cases[i]
		in := mustHex(t, c.Bytes)
		var n *Noun
		var tr Trap
		switch c.Role {
		case "formula":
			n, tr = DecodeFormula(in)
		case "subject":
			n, tr = DecodeSubject(in)
		default:
			t.Fatalf("%s: unknown role %q", c.Name, c.Role)
		}
		switch c.Expect.Kind {
		case "noun":
			if tr != TrapNone {
				t.Fatalf("%s: decode trap %d, want noun", c.Name, tr)
			}
			if re := Encode(n); !bytes.Equal(re, in) {
				t.Fatalf("%s: encode(decode(b)) != b: %x", c.Name, re)
			}
		case "trap":
			if tr == TrapNone {
				t.Fatalf("%s: decoded, want trap %d", c.Name, *c.Expect.TrapCode)
			}
			if int(tr) != *c.Expect.TrapCode {
				t.Fatalf("%s: trap %d, want %d", c.Name, tr, *c.Expect.TrapCode)
			}
		default:
			t.Fatalf("%s: unknown expect kind %q", c.Name, c.Expect.Kind)
		}
	}
	t.Logf("noun-bytes vectors: %d cases", len(cases))
}

func TestHintErasureVectors(t *testing.T) {
	cases := loadVectors(t, "grain-hint-erasure-v1.json", "noos/grain/hint-erasure-v1")
	if len(cases) == 0 {
		t.Fatal("no hint-erasure cases")
	}
	for i := range cases {
		c := &cases[i]
		subj := mustHex(t, c.Subject)
		// Both the hinted and the erased formula, each against fresh meter
		// parameters, must equal expect exactly (spec §14).
		hinted := runEval(caseVersion(c), subj, mustHex(t, c.Bytes), c.MeterLimit, c.ArenaLimit)
		checkOutcome(t, c, hinted)
		erased := runEval(caseVersion(c), subj, mustHex(t, c.Erased), c.MeterLimit, c.ArenaLimit)
		checkOutcome(t, c, erased)
	}
	t.Logf("hint-erasure vectors: %d cases (each run hinted + erased)", len(cases))
}

// TestVectorCount pins the frozen corpus size: 52 eval + 21 noun-bytes +
// 5 hint-erasure = 78 cases. A change here means the frozen inputs moved.
func TestVectorCount(t *testing.T) {
	n := len(loadVectors(t, "grain-eval-v1.json", "noos/grain/eval-v1")) +
		len(loadVectors(t, "grain-noun-bytes-v1.json", "noos/grain/noun-bytes-v1")) +
		len(loadVectors(t, "grain-hint-erasure-v1.json", "noos/grain/hint-erasure-v1"))
	if n != 78 {
		t.Fatalf("vector corpus has %d cases, frozen count is 78", n)
	}
}
