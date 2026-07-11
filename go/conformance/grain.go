package conformance

import (
	"bytes"

	"github.com/mindchain/noosphere/go/grainref"
)

// Grain vector runners (protocol/vectors/grain/), driving the existing
// independent go/grainref evaluator under the §14 runner obligation
// order: version gate, decode subject, decode formula (decode traps
// report charge 0), eval.

type grainExpect struct {
	Kind     string  `json:"kind"`
	Noun     *string `json:"noun"`
	TrapCode *int    `json:"trap_code"`
	Charge   uint64  `json:"charge"`
}

type grainMeta struct {
	Subject    string      `json:"subject"`
	Formula    string      `json:"formula"`
	Erased     string      `json:"erased_formula"`
	Role       string      `json:"role"`
	Version    *uint32     `json:"version"`
	MeterLimit uint64      `json:"meter_limit"`
	ArenaLimit uint64      `json:"arena_limit"`
	Expect     grainExpect `json:"expect"`
}

type grainOutcome struct {
	trap   grainref.Trap
	noun   []byte
	charge uint64
}

func grainEval(version uint32, subjectHex, formulaHex []byte, meterLimit, arenaLimit uint64) grainOutcome {
	m := grainref.NewMeter(meterLimit, arenaLimit)
	if version != grainref.GrainVersion {
		_, tr := grainref.Eval(version, nil, nil, m)
		return grainOutcome{trap: tr, charge: m.Spent()}
	}
	subj, tr := grainref.DecodeSubject(subjectHex)
	if tr != grainref.TrapNone {
		return grainOutcome{trap: tr}
	}
	form, tr := grainref.DecodeFormula(formulaHex)
	if tr != grainref.TrapNone {
		return grainOutcome{trap: tr}
	}
	res, tr := grainref.Eval(version, subj, form, m)
	if tr != grainref.TrapNone {
		return grainOutcome{trap: tr, charge: m.Spent()}
	}
	return grainOutcome{noun: grainref.Encode(res), charge: m.Spent()}
}

func scoreGrain(c *vecCase, meta *grainMeta, got grainOutcome) CaseResult {
	exp := meta.Expect
	switch exp.Kind {
	case "value":
		if got.trap != grainref.TrapNone {
			return bad(c.Name, "trap %d, want value", got.trap)
		}
		if exp.Noun != nil && !bytes.Equal(got.noun, mustHex(*exp.Noun)) {
			return bad(c.Name, "noun mismatch")
		}
	case "trap":
		if got.trap == grainref.TrapNone {
			return bad(c.Name, "value, want trap %d", derefInt(exp.TrapCode))
		}
		if exp.TrapCode != nil && int(got.trap) != *exp.TrapCode {
			return bad(c.Name, "trap %d, want %d", got.trap, *exp.TrapCode)
		}
	default:
		return bad(c.Name, "unknown expect kind %q", exp.Kind)
	}
	if got.charge != exp.Charge {
		return bad(c.Name, "charge %d, want %d", got.charge, exp.Charge)
	}
	return ok(c.Name)
}

func derefInt(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func runGrainEval(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta grainMeta
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		version := grainref.GrainVersion
		if meta.Version != nil {
			version = *meta.Version
		}
		got := grainEval(version, mustHex(meta.Subject), mustHex(meta.Formula), meta.MeterLimit, meta.ArenaLimit)
		out = append(out, scoreGrain(c, &meta, got))
	}
	return out
}

func runGrainNounBytes(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta grainMeta
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		b := mustHex(c.Bytes)
		var noun *grainref.Noun
		var tr grainref.Trap
		if meta.Role == "subject" {
			noun, tr = grainref.DecodeSubject(b)
		} else {
			noun, tr = grainref.DecodeFormula(b)
		}
		if c.Kind == "positive" {
			if tr != grainref.TrapNone {
				out = append(out, bad(c.Name, "trap %d decoding canonical bytes", tr))
				continue
			}
			if !bytes.Equal(grainref.Encode(noun), b) {
				out = append(out, bad(c.Name, "re-encode differs"))
				continue
			}
			out = append(out, ok(c.Name))
			continue
		}
		if tr == grainref.TrapNone {
			out = append(out, bad(c.Name, "malformed bytes decoded"))
			continue
		}
		if meta.Expect.TrapCode != nil && int(tr) != *meta.Expect.TrapCode {
			out = append(out, bad(c.Name, "trap %d, want %d", tr, *meta.Expect.TrapCode))
			continue
		}
		out = append(out, ok(c.Name))
	}
	return out
}

func runGrainHintErasure(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta grainMeta
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		version := grainref.GrainVersion
		if meta.Version != nil {
			version = *meta.Version
		}
		subj := mustHex(meta.Subject)
		// Both the hinted formula (bytes) and the erased formula, each
		// against fresh meter parameters, must equal expect exactly:
		// removing a hint preserves noun, trap, and semantic charge.
		hinted := grainEval(version, subj, mustHex(c.Bytes), meta.MeterLimit, meta.ArenaLimit)
		if r := scoreGrain(c, &meta, hinted); r.Status != Pass {
			out = append(out, r)
			continue
		}
		erased := grainEval(version, subj, mustHex(meta.Erased), meta.MeterLimit, meta.ArenaLimit)
		out = append(out, scoreGrain(c, &meta, erased))
	}
	return out
}
