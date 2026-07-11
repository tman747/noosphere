package conformance

import (
	"bytes"
	"encoding/binary"

	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Lumen vector runners (protocol/vectors/lumen/).

// runLumenSMT: bytes = expected_root(32) || u32 count || (key(32) ||
// u32 len || value)*; rebuild the tree and compare roots. Negative cases
// carry a claimed root the honest rebuild must NOT reproduce.
func runLumenSMT(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		b := mustHex(c.Bytes)
		if len(b) < 36 {
			out = append(out, bad(c.Name, "vector shorter than header"))
			continue
		}
		var claimed [32]byte
		copy(claimed[:], b[:32])
		n := binary.LittleEndian.Uint32(b[32:36])
		off := 36
		var t lumenref.SMT
		okShape := true
		for range n {
			if off+36 > len(b) {
				okShape = false
				break
			}
			var key [32]byte
			copy(key[:], b[off:off+32])
			ln := int(binary.LittleEndian.Uint32(b[off+32 : off+36]))
			off += 36
			if off+ln > len(b) {
				okShape = false
				break
			}
			t.Put(key, b[off:off+ln])
			off += ln
		}
		if !okShape || off != len(b) {
			out = append(out, bad(c.Name, "malformed smt vector payload"))
			continue
		}
		got := t.Root()
		match := got == claimed
		if (c.Kind == "positive") == match {
			out = append(out, ok(c.Name))
		} else if c.Kind == "positive" {
			out = append(out, bad(c.Name, "root mismatch"))
		} else {
			out = append(out, bad(c.Name, "honest rebuild reproduced a wrong-law root"))
		}
	}
	return out
}

// runLumenIDs: bytes = claimed_id(32) || preimage; the preimage layout
// depends on id_kind. Recompute and compare; negatives must not match.
func runLumenIDs(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			IDKind string `json:"id_kind"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		b := mustHex(c.Bytes)
		var claimed [32]byte
		copy(claimed[:], b[:32])
		rest := b[32:]
		var got [32]byte
		var err error
		switch meta.IDKind {
		case "note_id":
			var txid [32]byte
			copy(txid[:], rest[:32])
			idx := binary.LittleEndian.Uint32(rest[32:36])
			var note lumenref.NoteV1
			note, err = lumenref.DecodeNote(rest[36:])
			if err == nil {
				got = lumenref.NoteID(txid, idx, &note)
			}
		case "txid":
			var tx *lumenref.TransactionV1
			tx, err = lumenref.DecodeTransaction(rest)
			if err == nil {
				got = lumenref.TxID(tx)
			}
		case "wtxid":
			// preimage = u32 body length || body || witnesses
			bl := binary.LittleEndian.Uint32(rest[:4])
			body := rest[4 : 4+bl]
			wit := rest[4+bl:]
			var tx *lumenref.TransactionV1
			var tw *lumenref.TransactionWitnessesV1
			tx, err = lumenref.DecodeTransaction(body)
			if err == nil {
				tw, err = lumenref.DecodeWitnesses(wit)
			}
			if err == nil {
				got = lumenref.WTxID(tx, tw)
			}
		default:
			out = append(out, bad(c.Name, "unknown id_kind %q", meta.IDKind))
			continue
		}
		if err != nil {
			out = append(out, bad(c.Name, "preimage decode: %v", err))
			continue
		}
		match := got == claimed
		if (c.Kind == "positive") == match {
			out = append(out, ok(c.Name))
		} else if c.Kind == "positive" {
			out = append(out, bad(c.Name, "id mismatch"))
		} else {
			out = append(out, bad(c.Name, "claimed id verified but must reject"))
		}
	}
	return out
}

// runLumenTx: envelope decode law. Positives roundtrip byte-identically;
// negatives reject. Two named cases decode standalone sub-objects.
func runLumenTx(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		b := mustHex(c.Bytes)
		var err error
		var reenc []byte
		switch c.Name {
		case "tx_witnesses_roundtrip":
			var tw *lumenref.TransactionWitnessesV1
			if tw, err = lumenref.DecodeWitnesses(b); err == nil {
				reenc = tw.Encode()
			}
		case "access_entry_mode_invalid":
			r := codec.NewReader(b)
			if _, err = lumenref.DecodeObjectAccessEntryFrom(r); err == nil {
				err = r.Finish()
			}
		default:
			var tx *lumenref.TransactionV1
			if tx, err = lumenref.DecodeTransaction(b); err == nil {
				reenc = tx.Encode()
			}
		}
		if c.Kind == "positive" && err == nil && reenc != nil && !bytes.Equal(reenc, b) {
			out = append(out, bad(c.Name, "re-encode differs from canonical input"))
			continue
		}
		out = append(out, expectOutcome(c, err, nil))
	}
	return out
}
