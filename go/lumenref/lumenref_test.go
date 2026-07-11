package lumenref

import (
	"testing"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// SMT behavioral contracts beyond the vector corpus (lumen-v1.md §2):
// insertion-order independence, duplicate-key replacement, and
// delete-restores-prior-root.

func key(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func TestSMTInsertionOrderIndependence(t *testing.T) {
	var a, b SMT
	entries := [][32]byte{key(1), key(0x80), key(0x81), key(0xff), key(0)}
	for i, k := range entries {
		a.Put(k, []byte{byte(i)})
	}
	for i := len(entries) - 1; i >= 0; i-- {
		b.Put(entries[i], []byte{byte(i)})
	}
	if a.Root() != b.Root() {
		t.Fatal("root depends on insertion order")
	}
}

func TestSMTDeleteRestoresRoot(t *testing.T) {
	var s SMT
	s.Put(key(1), []byte("one"))
	before := s.Root()
	s.Put(key(2), []byte("two"))
	if s.Root() == before {
		t.Fatal("insert did not change the root")
	}
	s.Delete(key(2))
	if s.Root() != before {
		t.Fatal("delete did not restore the prior root")
	}
}

func TestSMTDuplicateKeyReplaces(t *testing.T) {
	var a, b SMT
	a.Put(key(1), []byte("x"))
	a.Put(key(1), []byte("y"))
	b.Put(key(1), []byte("y"))
	if a.Root() != b.Root() {
		t.Fatal("duplicate-key update must replace the value")
	}
	if a.Len() != 1 {
		t.Fatalf("len %d, want 1", a.Len())
	}
}

func TestSMTEmptyRootIsDerivedConstant(t *testing.T) {
	var s SMT
	if s.Root() != SMTEmptyRoot(256) {
		t.Fatal("empty tree root must be E[256]")
	}
}

// Codec writer/reader inverse law on every primitive.
func TestCodecRoundtrip(t *testing.T) {
	w := codec.NewWriter()
	w.U8(0xab)
	w.U16(0x0102)
	w.U32(0x01020304)
	w.U64(0x0102030405060708)
	w.U128(codec.U128{Lo: 1, Hi: 2})
	w.VarBytes([]byte("noos"))
	w.Presence(true)
	r := codec.NewReader(w.Bytes())
	if v, _ := r.U8(); v != 0xab {
		t.Fatal("u8")
	}
	if v, _ := r.U16(); v != 0x0102 {
		t.Fatal("u16")
	}
	if v, _ := r.U32(); v != 0x01020304 {
		t.Fatal("u32")
	}
	if v, _ := r.U64(); v != 0x0102030405060708 {
		t.Fatal("u64")
	}
	if v, _ := r.U128(); v.Lo != 1 || v.Hi != 2 {
		t.Fatal("u128")
	}
	if b, _ := r.VarBytes(16); string(b) != "noos" {
		t.Fatal("varbytes")
	}
	if p, _ := r.OptionalPresence(); !p {
		t.Fatal("presence")
	}
	if err := r.Finish(); err != nil {
		t.Fatalf("finish: %v", err)
	}
}

// The witness root commits programs only: signatures cannot malleate it,
// but a changed reveal changes it (lumen-v1.md §4.2).
func TestWitnessRootCommitsProgramsOnly(t *testing.T) {
	a := WitnessRoot([][]byte{{1, 2, 3}})
	b := WitnessRoot([][]byte{{1, 2, 4}})
	if a == b {
		t.Fatal("witness root must bind lock reveals")
	}
	if a == WitnessRoot(nil) {
		t.Fatal("witness root must bind the reveal count")
	}
}

// Distinct-domain law: txid never verifies as wtxid even for a
// witness-free transaction.
func TestTxIDDistinctFromWTxID(t *testing.T) {
	tx := &TransactionV1{FormatVersion: 1}
	if TxID(tx) == WTxID(tx, &TransactionWitnessesV1{}) {
		t.Fatal("txid and wtxid domains must be distinct")
	}
}
