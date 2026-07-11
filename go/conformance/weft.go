package conformance

import (
	"encoding/hex"
	"strings"

	"github.com/mindchain/noosphere/go/receiptref"
)

// Weft v0 vector runner (protocol/vectors/weft/) — DECODE-LEVEL ONLY.
//
// The base client certifies the canonical decode law (frozen codes 1–7,
// 10) and the §3 content-addressing law. Cases whose expected rejection
// is a §5 checker-semantics code (20..79) require the go/weftref relation
// checker (profile consistency, store-resolved reference integrity,
// cost-trial Grain evaluation) and are reported as SKIP — the recorded
// checker-semantics seam — never silently dropped and never counted as
// pass.

type weftExpect struct {
	Result     string `json:"result"`
	ContentID  string `json:"content_id"`
	ErrorCode  int    `json:"error_code"`
	ErrorClass string `json:"error_class"`
}

func runWeft(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			Object string     `json:"object"`
			Expect weftExpect `json:"expect"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		id, err := receiptref.DecodeWeftObject(meta.Object, mustHex(c.Bytes))
		switch meta.Expect.Result {
		case "accept":
			if err != nil {
				out = append(out, bad(c.Name, "decode: %v", err))
				continue
			}
			if hex.EncodeToString(id[:]) != meta.Expect.ContentID {
				out = append(out, bad(c.Name, "content id mismatch"))
				continue
			}
			// Decode + content id verified; the semantic accept
			// itself is weftref's obligation.
			out = append(out, ok(c.Name))
		case "reject":
			if strings.HasPrefix(meta.Expect.ErrorClass, "decode_") ||
				meta.Expect.ErrorClass == "unknown_object_kind" {
				if err == nil {
					out = append(out, bad(c.Name, "expected decode reject %q, decoded", meta.Expect.ErrorClass))
					continue
				}
				we, isWeft := err.(*receiptref.WeftError)
				if !isWeft || we.Code != meta.Expect.ErrorCode || we.Class != meta.Expect.ErrorClass {
					out = append(out, bad(c.Name, "got %v, want %d %s", err, meta.Expect.ErrorCode, meta.Expect.ErrorClass))
					continue
				}
				out = append(out, ok(c.Name))
				continue
			}
			// Checker-semantics case: it MUST at least decode
			// canonically; the semantic rejection is the seam.
			if err != nil {
				out = append(out, bad(c.Name, "semantic case failed decode: %v", err))
				continue
			}
			out = append(out, skip(c.Name, "checker-semantics seam (go/weftref): "+meta.Expect.ErrorClass))
		default:
			out = append(out, bad(c.Name, "unknown expect result %q", meta.Expect.Result))
		}
	}
	return out
}
