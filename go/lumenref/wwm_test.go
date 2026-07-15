package lumenref

import (
	"encoding/binary"
	"testing"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

func minimalArtifactPayload() []byte {
	w := codec.NewWriter()
	w.Version(1)
	tag := uint16(1)
	next := func() { w.Tag(tag); tag++ }
	next()
	w.Hash32([32]byte{})
	next()
	w.U16(0)
	next()
	w.U64(0)
	for range 3 {
		next()
		w.Hash32([32]byte{})
	}
	next()
	w.U16(0)
	next()
	w.U32(0)
	for range 4 {
		next()
		w.Hash32([32]byte{})
	}
	next()
	w.U64(0)
	next()
	w.U32(0)
	return w.Bytes()
}

func actionBytes(discriminant uint16, payload []byte) []byte {
	b := make([]byte, 2, len(payload)+2)
	binary.LittleEndian.PutUint16(b, discriminant)
	return append(b, payload...)
}

func TestWwmActionDiscriminantsAndStrictObjectTags(t *testing.T) {
	for d := WwmActionFirst; d < WwmActionCount; d++ {
		if _, ok := wwmSchema(d); !ok {
			t.Fatalf("missing schema for action %d", d)
		}
	}
	for _, d := range []uint16{39, 60, 61, 65535} {
		_, err := DecodeWwmAction(actionBytes(d, nil))
		if codec.ClassOf(err) != codec.ErrUnknownDiscriminant {
			t.Fatalf("action %d: %v", d, err)
		}
	}
	good := actionBytes(40, minimalArtifactPayload())
	decoded, err := DecodeWwmAction(good)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(good) {
		t.Fatal("roundtrip mismatch")
	}
	trailing := append(append([]byte(nil), good...), 0)
	if _, err = DecodeWwmAction(trailing); codec.ClassOf(err) != codec.ErrTrailingBytes {
		t.Fatalf("trailing: %v", err)
	}
	badVersion := append([]byte(nil), good...)
	badVersion[2] = 2
	if _, err = DecodeWwmAction(badVersion); codec.ClassOf(err) != codec.ErrUnknownVersion {
		t.Fatalf("version: %v", err)
	}
	badTag := append([]byte(nil), good...)
	badTag[4] = 2
	if _, err = DecodeWwmAction(badTag); codec.ClassOf(err) != codec.ErrUnknownMandatoryField {
		t.Fatalf("tag: %v", err)
	}
}

func TestWwmNestedPayloadTagsAndCarrierEdges(t *testing.T) {
	for _, tc := range []struct {
		d   uint16
		tag byte
	}{{41, 2}, {50, 2}, {52, 4}, {59, 5}} {
		_, err := DecodeWwmAction(actionBytes(tc.d, []byte{tc.tag}))
		if codec.ClassOf(err) != codec.ErrUnknownDiscriminant {
			t.Fatalf("action %d tag %d: %v", tc.d, tc.tag, err)
		}
	}
	if !CarrierLenValid(0, 65_532) || !CarrierLenValid(65_532, 0) || CarrierLenValid(65_533, 0) || CarrierLenValid(-1, 0) {
		t.Fatal("carrier edge law")
	}
}
