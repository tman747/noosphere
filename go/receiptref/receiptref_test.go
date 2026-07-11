package receiptref

import (
	"testing"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

func encodeLeaf(verifier uint32, kind byte, journal byte, proof []byte) []byte {
	w := codec.NewWriter()
	w.Hash32([32]byte{1})
	w.U32(verifier)
	w.U8(kind)
	var j [32]byte
	j[0] = journal
	w.Hash32(j)
	w.VarBytes(proof)
	return w.Bytes()
}

// The registry is CLOSED: an unknown verifier id rejects at decode,
// before any proof work.
func TestUnknownVerifierRejectsAtDecode(t *testing.T) {
	if _, err := DecodeLeafReceipt(encodeLeaf(999, 0, 1, nil)); err == nil {
		t.Fatal("unknown verifier id decoded")
	}
}

// Disabled SpecializedChunkV1 dispatches to an explicit reject.
func TestDisabledVerifierRejects(t *testing.T) {
	env, err := DecodeLeafReceipt(encodeLeaf(uint32(VerifierSpecializedChunkV1), 0, 1, nil))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v := Dispatch(env); v.Accepted {
		t.Fatal("disabled verifier accepted")
	}
}

// A registered verifier without a backend REJECTS — there is no fallback
// to acceptance anywhere in dispatch.
func TestMissingBackendRejects(t *testing.T) {
	env, err := DecodeLeafReceipt(encodeLeaf(uint32(VerifierRisc0FreivaldsLeaf), 0, 1, []byte{1, 2}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v := Dispatch(env); v.Accepted {
		t.Fatal("backend-less verifier accepted")
	}
}

// EnvelopeV1 accepts only the decode-level profile: nonzero journal
// commitment, zero proof payload.
func TestEnvelopeV1Profile(t *testing.T) {
	env, err := DecodeLeafReceipt(encodeLeaf(uint32(VerifierEnvelopeV1), 1, 1, nil))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v := Dispatch(env); !v.Accepted {
		t.Fatalf("valid envelope rejected: %s", v.Reason)
	}
	zeroJournal, err := DecodeLeafReceipt(encodeLeaf(uint32(VerifierEnvelopeV1), 0, 0, nil))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v := Dispatch(zeroJournal); v.Accepted {
		t.Fatal("zero journal commitment accepted")
	}
}

// Unknown leaf kinds and trailing bytes reject at decode.
func TestLeafDecodeLaw(t *testing.T) {
	if _, err := DecodeLeafReceipt(encodeLeaf(uint32(VerifierEnvelopeV1), 2, 1, nil)); err == nil {
		t.Fatal("unknown leaf kind decoded")
	}
	b := append(encodeLeaf(uint32(VerifierEnvelopeV1), 0, 1, nil), 0)
	if _, err := DecodeLeafReceipt(b); err == nil {
		t.Fatal("trailing byte decoded")
	}
}

// Unknown weft object kinds reject with the frozen code 10.
func TestWeftUnknownKind(t *testing.T) {
	_, err := DecodeWeftObject("mystery", []byte{0, 0})
	we, ok := err.(*WeftError)
	if !ok || we.Code != 10 || we.Class != "unknown_object_kind" {
		t.Fatalf("got %v, want 10 unknown_object_kind", err)
	}
}
