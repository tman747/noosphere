package conformance

import (
	"bytes"
	"strings"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Codec vector runner (protocol/vectors/codec/codec-v1.json). Each case
// name selects its decode context, exactly as the vector notes state
// ("ctx: get_bytes max=16", "ctx: get_list<u64> max=8", ...). DemoV1 is
// the vector fixture object: u16 version 1; tag 1 u64; tag 2 fixed 32
// bytes; tag 3 u16.

func codecClass(err error) string { return string(codec.ClassOf(err)) }

func decodeDemo(b []byte) ([]byte, error) {
	r := codec.NewReader(b)
	if err := r.Version(1); err != nil {
		return nil, err
	}
	if err := r.Tag(1); err != nil {
		return nil, err
	}
	f1, err := r.U64()
	if err != nil {
		return nil, err
	}
	if err := r.Tag(2); err != nil {
		return nil, err
	}
	f2, err := r.Fixed(32)
	if err != nil {
		return nil, err
	}
	if err := r.Tag(3); err != nil {
		return nil, err
	}
	f3, err := r.U16()
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	w := codec.NewWriter()
	w.Version(1)
	w.Tag(1)
	w.U64(f1)
	w.Tag(2)
	w.Fixed(f2)
	w.Tag(3)
	w.U16(f3)
	return w.Bytes(), nil
}

func runCodec(cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		out = append(out, runCodecCase(c))
	}
	return out
}

func runCodecCase(c *vecCase) CaseResult {
	input := mustHex(c.Bytes)
	name := c.Name
	whole := func(f func(r *codec.Reader) error) error {
		r := codec.NewReader(input)
		if err := f(r); err != nil {
			return err
		}
		return r.Finish()
	}
	var err error
	var reenc []byte
	switch {
	case strings.HasPrefix(name, "demo_"):
		reenc, err = decodeDemo(input)
		if err == nil && !bytes.Equal(reenc, input) {
			return bad(name, "re-encode differs from canonical input")
		}
	case name == "prim_u8":
		err = whole(func(r *codec.Reader) error { _, e := r.U8(); return e })
	case name == "prim_u16_le":
		err = whole(func(r *codec.Reader) error { _, e := r.U16(); return e })
	case name == "prim_u32_le":
		err = whole(func(r *codec.Reader) error { _, e := r.U32(); return e })
	case name == "prim_u64_le":
		err = whole(func(r *codec.Reader) error { _, e := r.U64(); return e })
	case name == "prim_u128_one":
		err = whole(func(r *codec.Reader) error {
			v, e := r.U128()
			if e == nil && (v.Lo != 1 || v.Hi != 0) {
				return &codec.Error{Class: codec.ErrInvalidValue, Context: "u128 value"}
			}
			return e
		})
	case name == "prim_array32":
		err = whole(func(r *codec.Reader) error { _, e := r.Fixed(32); return e })
	case strings.HasPrefix(name, "bytes_"):
		err = whole(func(r *codec.Reader) error { _, e := r.VarBytes(16); return e })
	case strings.HasPrefix(name, "atom_"):
		err = whole(func(r *codec.Reader) error { _, e := r.Atom(16); return e })
	case name == "optional_field":
		err = whole(func(r *codec.Reader) error {
			present, e := r.OptionalTag(1)
			if e != nil {
				return e
			}
			if !present {
				return &codec.Error{Class: codec.ErrUnknownMandatoryField, Context: "optional tag absent"}
			}
			_, e = r.VarBytes(16)
			return e
		})
	case strings.HasPrefix(name, "list_u16_"):
		err = whole(func(r *codec.Reader) error {
			n, e := r.ListLen(8, 2)
			if e != nil {
				return e
			}
			for range n {
				if _, e = r.U16(); e != nil {
					return e
				}
			}
			return nil
		})
	case name == "list_huge_count_no_alloc":
		err = whole(func(r *codec.Reader) error {
			// ctx: get_list<u64> max=2^32-1 — only the byte-floor
			// check can stop the forged count.
			n, e := r.ListLen(^uint32(0), 8)
			if e != nil {
				return e
			}
			for range n {
				if _, e = r.U64(); e != nil {
					return e
				}
			}
			return nil
		})
	case strings.HasPrefix(name, "list_"):
		err = whole(func(r *codec.Reader) error {
			// ctx: get_list<u64> max=8
			n, e := r.ListLen(8, 8)
			if e != nil {
				return e
			}
			for range n {
				if _, e = r.U64(); e != nil {
					return e
				}
			}
			return nil
		})
	case strings.HasPrefix(name, "discriminant_"):
		err = whole(func(r *codec.Reader) error { _, e := r.Discriminant(3); return e })
	default:
		return bad(name, "no decode context for this case name")
	}
	return expectOutcome(c, err, codecClass)
}
