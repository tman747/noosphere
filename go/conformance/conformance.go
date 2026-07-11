// Package conformance runs the frozen protocol/vectors corpus through the
// independent Go base client (lumenref, braidref, receiptref, grainref).
// It is consumed by go test and by the noos-verify CLI.
//
// INDEPENDENCE ATTESTATION (plan §8.5): the runners interpret only the
// frozen vector JSON files and the frozen schema documents; no Rust
// source was read and no oracle was copied.
package conformance

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Status of one vector case.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	// Skip marks a case whose expectation needs machinery this base
	// client intentionally does not implement (the recorded
	// checker-semantics seam); it is never counted as a failure but is
	// reported so nothing silently narrows.
	Skip Status = "skip"
)

// CaseResult is the outcome of one case.
type CaseResult struct {
	Name   string
	Status Status
	Detail string
}

// FileReport aggregates one vector file.
type FileReport struct {
	File   string
	Schema string
	Cases  []CaseResult
}

// Counts returns (pass, fail, skip).
func (r *FileReport) Counts() (pass, fail, skip int) {
	for _, c := range r.Cases {
		switch c.Status {
		case Pass:
			pass++
		case Fail:
			fail++
		case Skip:
			skip++
		}
	}
	return
}

// vecCase is the shared vector case shape; family-specific fields are
// decoded from Raw by the runners.
type vecCase struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Bytes      string `json:"bytes"`
	Note       string `json:"note"`
	ErrorClass string `json:"error_class"`

	raw json.RawMessage
}

type vecFile struct {
	Schema string            `json:"schema"`
	Cases  []json.RawMessage `json:"cases"`
}

func loadFile(path string) (string, []vecCase, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var f vecFile
	if err := json.Unmarshal(blob, &f); err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	cases := make([]vecCase, 0, len(f.Cases))
	for i, raw := range f.Cases {
		var c vecCase
		if err := json.Unmarshal(raw, &c); err != nil {
			return "", nil, fmt.Errorf("%s case %d: %w", path, i, err)
		}
		c.raw = raw
		cases = append(cases, c)
	}
	return f.Schema, cases, nil
}

func (c *vecCase) into(v any) error { return json.Unmarshal(c.raw, v) }

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad vector hex: %v", err))
	}
	return b
}

func hex32(s string) [32]byte {
	var h [32]byte
	copy(h[:], mustHex(s))
	return h
}

func hex48(s string) [48]byte {
	var h [48]byte
	copy(h[:], mustHex(s))
	return h
}

// runCtx carries the vector root so runners can load shared fixtures
// (e.g. the four-member membership snapshot referenced by the vote,
// certificate, slashing, and beacon vectors).
type runCtx struct {
	root string // protocol/vectors directory containing this file
}

// runner executes one family of cases.
type runner func(ctx *runCtx, cases []vecCase) []CaseResult

// runners keyed by the frozen schema string of each vector file.
var runners = map[string]runner{
	"noos-codec-vectors-v1":             runCodec,
	"noos-lumen/smt-v1":                 runLumenSMT,
	"noos-lumen/ids-v1":                 runLumenIDs,
	"noos-lumen/tx-v1":                  runLumenTx,
	"noos-braid/header-v1":              runBraidHeader,
	"noos-braid/header-validation-v1":   runBraidValidation,
	"noos-braid/proposal-commitment-v1": runBraidCommitment,
	"noos-braid/fork-choice-v1":         runBraidForkChoice,
	"noos-braid/body-v1":                runBraidBody,
	"noos-ground/ticket-v1":             runGroundTicket,
	"noos-ground/pulse-v1":              runPulse,
	"noos-witness/vote-v1":              runWitnessVote,
	"noos-witness/certificate-v1":       runWitnessCertificate,
	"noos-witness/membership-v1":        runWitnessMembership,
	"noos-witness/threshold-v1":         runWitnessThreshold,
	"noos-witness/bond-v1":              runWitnessBond,
	"noos-witness/slashing-v1":          runWitnessSlashing,
	"noos-witness/beacon-v1":            runWitnessBeacon,
	"noos/grain/eval-v1":                runGrainEval,
	"noos/grain/noun-bytes-v1":          runGrainNounBytes,
	"noos/grain/hint-erasure-v1":        runGrainHintErasure,
	"noos/weft/refs-v0":                 runWeft,
	"noos/weft/cost-v0":                 runWeft,
	"noos/weft/profile-v0":              runWeft,
}

// Understands reports whether a schema has a runner.
func Understands(schema string) bool {
	_, ok := runners[schema]
	return ok
}

// RunFile executes one vector file. Files with an unknown schema return
// (nil, nil) so callers can report them as not-understood.
func RunFile(path string) (*FileReport, error) {
	schema, cases, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	run, ok := runners[schema]
	if !ok {
		return nil, nil
	}
	ctx := &runCtx{root: filepath.Dir(filepath.Dir(path))}
	rep := &FileReport{File: filepath.ToSlash(path), Schema: schema}
	rep.Cases = run(ctx, cases)
	return rep, nil
}

// VectorFiles lists every *.json under root/<family>/ in stable order.
func VectorFiles(root string) ([]string, error) {
	var out []string
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := filepath.Glob(filepath.Join(root, e.Name(), "*.json"))
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	sort.Strings(out)
	return out, nil
}

// FindVectorRoot walks up from dir looking for protocol/vectors.
func FindVectorRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		cand := filepath.Join(abs, "protocol", "vectors")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fmt.Errorf("protocol/vectors not found above %s", dir)
		}
		abs = parent
	}
}

// pass/fail helpers.
func ok(name string) CaseResult { return CaseResult{Name: name, Status: Pass} }
func bad(name, format string, args ...any) CaseResult {
	return CaseResult{Name: name, Status: Fail, Detail: fmt.Sprintf(format, args...)}
}
func skip(name, detail string) CaseResult {
	return CaseResult{Name: name, Status: Skip, Detail: detail}
}

// expectOutcome scores a decode-style case: positives must succeed;
// negatives must fail, and when the vector pins an error class the
// produced class must match exactly.
func expectOutcome(c *vecCase, err error, classOf func(error) string) CaseResult {
	if c.Kind == "positive" {
		if err != nil {
			return bad(c.Name, "expected accept, got %v", err)
		}
		return ok(c.Name)
	}
	if err == nil {
		return bad(c.Name, "expected reject, got accept")
	}
	if c.ErrorClass != "" && classOf != nil {
		if got := classOf(err); got != c.ErrorClass {
			return bad(c.Name, "error class %q, want %q (%v)", got, c.ErrorClass, err)
		}
	}
	return ok(c.Name)
}
