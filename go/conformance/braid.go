package conformance

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/mindchain/noosphere/go/braidref"
)

// Braid vector runners (protocol/vectors/braid/).

func runBraidHeader(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			BlockHash          string `json:"block_hash"`
			ProposalCommitment string `json:"proposal_commitment"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		b := mustHex(c.Bytes)
		h, err := braidref.DecodeHeader(b)
		if c.Kind == "negative" {
			out = append(out, expectOutcome(c, err, codecClass))
			continue
		}
		if err != nil {
			out = append(out, bad(c.Name, "decode: %v", err))
			continue
		}
		if !bytes.Equal(h.Encode(), b) {
			out = append(out, bad(c.Name, "re-encode differs"))
			continue
		}
		if got := h.BlockHash(); hex.EncodeToString(got[:]) != meta.BlockHash {
			out = append(out, bad(c.Name, "block hash mismatch"))
			continue
		}
		if got := h.ProposalCommitment(); hex.EncodeToString(got[:]) != meta.ProposalCommitment {
			out = append(out, bad(c.Name, "proposal commitment mismatch"))
			continue
		}
		out = append(out, ok(c.Name))
	}
	return out
}

func runBraidValidation(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			ChainID string `json:"chain_id"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		h, err := braidref.DecodeHeader(mustHex(c.Bytes))
		if err != nil {
			out = append(out, bad(c.Name, "decode: %v", err))
			continue
		}
		err = braidref.ValidateStructure(h, hex32(meta.ChainID))
		out = append(out, expectOutcome(c, err, func(e error) string {
			if ve, okk := e.(*braidref.ValidationError); okk {
				return string(ve.Class)
			}
			return ""
		}))
	}
	return out
}

func runBraidCommitment(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			ProposalCommitment string `json:"proposal_commitment"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		h, err := braidref.DecodeHeader(mustHex(c.Bytes))
		if err != nil {
			out = append(out, bad(c.Name, "decode: %v", err))
			continue
		}
		got := h.ProposalCommitment()
		match := hex.EncodeToString(got[:]) == meta.ProposalCommitment
		if (c.Kind == "positive") == match {
			out = append(out, ok(c.Name))
		} else if c.Kind == "positive" {
			out = append(out, bad(c.Name, "commitment mismatch"))
		} else {
			out = append(out, bad(c.Name, "forged commitment claim verified"))
		}
	}
	return out
}

// runBraidForkChoice: bytes = two 80-byte branch tuples (finalized_epoch
// u64 || justified_epoch u64 || work u256 LE || block_hash 32); expected
// names the winner ("a" = first).
func runBraidForkChoice(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			Expected string `json:"expected"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		b := mustHex(c.Bytes)
		if len(b) != 160 {
			out = append(out, bad(c.Name, "tuple payload length %d", len(b)))
			continue
		}
		parse := func(p []byte) braidref.ForkTuple {
			var t braidref.ForkTuple
			t.FinalizedEpoch = binary.LittleEndian.Uint64(p[:8])
			t.JustifiedEpoch = binary.LittleEndian.Uint64(p[8:16])
			copy(t.WorkLE[:], p[16:48])
			copy(t.BlockHash[:], p[48:80])
			return t
		}
		a, bb := parse(b[:80]), parse(b[80:])
		winner := "b"
		if braidref.Compare(a, bb) > 0 {
			winner = "a"
		}
		if winner == meta.Expected {
			out = append(out, ok(c.Name))
		} else {
			out = append(out, bad(c.Name, "winner %s, want %s", winner, meta.Expected))
		}
	}
	return out
}

func runBraidBody(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		_, err := braidref.DecodeBody(mustHex(c.Bytes))
		out = append(out, expectOutcome(c, err, codecClass))
	}
	return out
}
