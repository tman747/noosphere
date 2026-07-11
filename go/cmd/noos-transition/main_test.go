package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func tag(b *bytes.Buffer, n uint16) { _ = binary.Write(b, binary.LittleEndian, n) }
func minimalTx() []byte {
	var b bytes.Buffer
	tag(&b, 1)
	tag(&b, 1)
	b.Write(bytes.Repeat([]byte{0x11}, 32))
	tag(&b, 2)
	tag(&b, 1)
	tag(&b, 3)
	_ = binary.Write(&b, binary.LittleEndian, uint64(10))
	tag(&b, 4)
	b.Write(bytes.Repeat([]byte{0x0f}, 32))
	tag(&b, 5)
	b.WriteByte(0)
	tag(&b, 6)
	b.Write(make([]byte, 48))
	for i := uint16(7); i <= 12; i++ {
		tag(&b, i)
		_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	}
	tag(&b, 13)
	b.Write(make([]byte, 32))
	return b.Bytes()
}
func TestCanonicalTransactionBounds(t *testing.T) {
	tx := minimalTx()
	if err := txDecode(tx); err != nil {
		t.Fatalf("canonical minimal transaction rejected: %v", err)
	}
	if err := txDecode(append(tx, 0)); err != decodeErr("TRAILING_BYTES") {
		t.Fatalf("trailing byte class = %v", err)
	}
	bad := append([]byte(nil), tx...)
	bad[0] = 2
	if err := txDecode(bad); err != decodeErr("UNKNOWN_VERSION") {
		t.Fatalf("version class = %v", err)
	}
}
func TestCanonicalWitnessAndSparseRoot(t *testing.T) {
	w := []byte{1, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0}
	reveals, err := witnessDecode(w)
	if err != nil {
		t.Fatal(err)
	}
	if len(reveals) != 4 {
		t.Fatalf("lock-reveal list encoding length=%d", len(reveals))
	}
	key := dh("NOOS/TX/ID/V1", minimalTx())
	if smtOne(key, []byte{1}) == emptyRoot {
		t.Fatal("receipt insertion did not change sparse root")
	}
}
