// Package codec implements the NOOSPHERE canonical wire codec law for the
// independent Go base client.
//
// INDEPENDENCE ATTESTATION: authored exclusively from the frozen documents
// (plan §3.1 codec law, protocol/spec/schema-tables/*.md, the wire-tag law in
// schema-tables/header-body.md) and the conformance vectors in
// protocol/vectors/codec/codec-v1.json. No Rust source under crates/noos-*
// was read; no code was generated or translated from another implementation.
//
// The law: fixed-width little-endian primitives; canonical u32-length-
// delimited bounded collections validated against BOTH the frozen maximum and
// the remaining input BEFORE allocation; consensus objects carry an explicit
// u16 version followed by u16 numeric mandatory tags in declaration order;
// enum discriminants are u16 in declaration order; optional fields carry a
// one-byte presence flag (0 or 1); atoms are minimal big-endian (zero is the
// empty string, a leading zero byte rejects); decoding consumes the entire
// input (trailing bytes reject).
package codec

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

// ErrorClass is a stable decode rejection class. The set is closed; the
// string values are exactly the error_class literals used by the frozen
// conformance vectors.
type ErrorClass string

const (
	ErrTruncated             ErrorClass = "truncated"
	ErrTrailingBytes         ErrorClass = "trailing_bytes"
	ErrUnknownVersion        ErrorClass = "unknown_version"
	ErrUnknownMandatoryField ErrorClass = "unknown_mandatory_field"
	ErrLengthExceedsBound    ErrorClass = "length_exceeds_bound"
	ErrNonminimalAtom        ErrorClass = "nonminimal_atom"
	ErrUnknownDiscriminant   ErrorClass = "unknown_discriminant"
	// ErrInvalidOptional is the presence-byte law: an optional field's
	// presence byte must be exactly 0 or 1.
	ErrInvalidOptional ErrorClass = "invalid_optional_presence"
	// ErrInvalidValue is a decode-level domain violation on a fixed-width
	// field (e.g. an object-access mode outside {0,1}).
	ErrInvalidValue ErrorClass = "invalid_value"
)

// Error is a typed decode rejection.
type Error struct {
	Class   ErrorClass
	Context string
}

func (e *Error) Error() string {
	if e.Context == "" {
		return string(e.Class)
	}
	return fmt.Sprintf("%s: %s", e.Class, e.Context)
}

func errf(class ErrorClass, format string, args ...any) *Error {
	return &Error{Class: class, Context: fmt.Sprintf(format, args...)}
}

// ClassOf returns the ErrorClass of a codec error, or "" for nil/foreign
// errors.
func ClassOf(err error) ErrorClass {
	if ce, ok := err.(*Error); ok {
		return ce.Class
	}
	return ""
}

// U128 is a little-endian 128-bit unsigned integer.
type U128 struct {
	Lo, Hi uint64
}

// Big returns the value as a new big.Int.
func (u U128) Big() *big.Int {
	v := new(big.Int).SetUint64(u.Hi)
	v.Lsh(v, 64)
	return v.Or(v, new(big.Int).SetUint64(u.Lo))
}

// IsZero reports whether the value is zero.
func (u U128) IsZero() bool { return u.Lo == 0 && u.Hi == 0 }

// U128FromUint64 widens a uint64.
func U128FromUint64(v uint64) U128 { return U128{Lo: v} }

// Reader decodes one canonical byte string. Every method returns a *Error
// with a stable class on violation; the reader never reads past the input.
type Reader struct {
	buf []byte
	off int
}

func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Remaining is the count of unconsumed bytes.
func (r *Reader) Remaining() int { return len(r.buf) - r.off }

func (r *Reader) take(n int) ([]byte, error) {
	if r.Remaining() < n {
		return nil, errf(ErrTruncated, "need %d bytes, have %d", n, r.Remaining())
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b, nil
}

func (r *Reader) U8() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *Reader) U16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *Reader) U32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *Reader) U64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (r *Reader) U128() (U128, error) {
	b, err := r.take(16)
	if err != nil {
		return U128{}, err
	}
	return U128{
		Lo: binary.LittleEndian.Uint64(b[:8]),
		Hi: binary.LittleEndian.Uint64(b[8:]),
	}, nil
}

// Fixed reads an n-byte fixed-width field (no length prefix).
func (r *Reader) Fixed(n int) ([]byte, error) {
	b, err := r.take(n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, b)
	return out, nil
}

// Hash32 reads a fixed 32-byte value.
func (r *Reader) Hash32() ([32]byte, error) {
	var h [32]byte
	b, err := r.take(32)
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}

// VarBytes reads a canonical u32-length-delimited byte string bounded by
// max. The declared length is validated against the bound AND the remaining
// input before any allocation.
func (r *Reader) VarBytes(max uint32) ([]byte, error) {
	n, err := r.U32()
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, errf(ErrLengthExceedsBound, "declared %d > max %d", n, max)
	}
	if int(n) > r.Remaining() {
		return nil, errf(ErrLengthExceedsBound, "declared %d > remaining %d", n, r.Remaining())
	}
	return r.Fixed(int(n))
}

// ListLen reads a canonical u32 collection count bounded by max. The
// byte-floor law fires BEFORE any allocation: a count exceeding the
// remaining input at one byte per element is a forged count and rejects
// as length_exceeds_bound. A count that passes the floor but whose
// elements outrun the input rejects later, per element, as truncated
// (the codec vectors pin both classes: list_huge_count_no_alloc vs
// list_element_truncated).
func (r *Reader) ListLen(max uint32) (uint32, error) {
	n, err := r.U32()
	if err != nil {
		return 0, err
	}
	if n > max {
		return 0, errf(ErrLengthExceedsBound, "count %d > max %d", n, max)
	}
	if uint64(n) > uint64(r.Remaining()) {
		return 0, errf(ErrLengthExceedsBound,
			"count %d exceeds %d remaining bytes", n, r.Remaining())
	}
	return n, nil
}

// Atom reads a canonical minimal big-endian unsigned atom bounded by max.
// Zero is the empty string; a leading zero byte is nonminimal and rejects.
func (r *Reader) Atom(max uint32) ([]byte, error) {
	b, err := r.VarBytes(max)
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, errf(ErrNonminimalAtom, "leading zero byte in %d-byte atom", len(b))
	}
	return b, nil
}

// Version reads the leading u16 object version and requires it to equal
// want.
func (r *Reader) Version(want uint16) error {
	v, err := r.U16()
	if err != nil {
		return err
	}
	if v != want {
		return errf(ErrUnknownVersion, "version %d, want %d", v, want)
	}
	return nil
}

// Tag reads a u16 mandatory field tag and requires it to equal want.
func (r *Reader) Tag(want uint16) error {
	t, err := r.U16()
	if err != nil {
		return err
	}
	if t != want {
		return errf(ErrUnknownMandatoryField, "tag %d, want %d", t, want)
	}
	return nil
}

// OptionalPresence reads a one-byte optional-field presence flag; any value
// other than 0 or 1 rejects.
func (r *Reader) OptionalPresence() (bool, error) {
	b, err := r.U8()
	if err != nil {
		return false, err
	}
	switch b {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errf(ErrInvalidOptional, "presence byte 0x%02x", b)
	}
}

// OptionalTag peeks a u16 tag; if it equals 0x8000|tag the tag is consumed
// and the optional field is present. This is the tagged-optional form used
// at the raw codec layer (codec vector "optional_field").
func (r *Reader) OptionalTag(tag uint16) (bool, error) {
	if r.Remaining() < 2 {
		return false, nil
	}
	t := binary.LittleEndian.Uint16(r.buf[r.off:])
	if t == 0x8000|tag {
		r.off += 2
		return true, nil
	}
	return false, nil
}

// Discriminant reads a u16 declaration-order enum discriminant with the
// given variant count.
func (r *Reader) Discriminant(count uint16) (uint16, error) {
	d, err := r.U16()
	if err != nil {
		return 0, err
	}
	if d >= count {
		return 0, errf(ErrUnknownDiscriminant, "discriminant %d, %d variants", d, count)
	}
	return d, nil
}

// Finish rejects any unconsumed trailing bytes; decoding must consume the
// whole input.
func (r *Reader) Finish() error {
	if n := r.Remaining(); n != 0 {
		return errf(ErrTrailingBytes, "%d trailing bytes", n)
	}
	return nil
}

// Writer builds a canonical encoding. It is the exact inverse of Reader and
// is used for re-encode (roundtrip) verification.
type Writer struct {
	buf []byte
}

func NewWriter() *Writer { return &Writer{} }

func (w *Writer) Bytes() []byte { return w.buf }

func (w *Writer) U8(v byte) { w.buf = append(w.buf, v) }
func (w *Writer) U16(v uint16) {
	w.buf = binary.LittleEndian.AppendUint16(w.buf, v)
}
func (w *Writer) U32(v uint32) {
	w.buf = binary.LittleEndian.AppendUint32(w.buf, v)
}
func (w *Writer) U64(v uint64) {
	w.buf = binary.LittleEndian.AppendUint64(w.buf, v)
}
func (w *Writer) U128(v U128) {
	w.U64(v.Lo)
	w.U64(v.Hi)
}
func (w *Writer) Fixed(b []byte)    { w.buf = append(w.buf, b...) }
func (w *Writer) Hash32(h [32]byte) { w.buf = append(w.buf, h[:]...) }
func (w *Writer) VarBytes(b []byte) {
	w.U32(uint32(len(b)))
	w.Fixed(b)
}
func (w *Writer) Version(v uint16) { w.U16(v) }
func (w *Writer) Tag(t uint16)     { w.U16(t) }
func (w *Writer) Presence(p bool) {
	if p {
		w.U8(1)
	} else {
		w.U8(0)
	}
}
