package receiptref

import (
	"fmt"

	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Weft v0 decode-level object law per protocol/schemas/weft-v0.md §§2–4
// and §6. This file implements the CANONICAL DECODE of the five v0
// objects with the exact frozen decode rejection codes (1–7, 10) and the
// §3 content-addressing law.
//
// CHECKER-SEMANTICS SEAM (recorded follow-up): the §5 relation checker —
// profile consistency, certificate-reference integrity against the
// admitted store, cost-trial Grain evaluation, span soundness/beacon
// policy (codes 20..70+) — belongs to go/weftref per plan §5.5 and is NOT
// implemented here. Decode-level acceptance plus content id is what this
// package certifies.

// Frozen v0 limits (weft-v0.md §2).
const (
	weftV0Version             = 0
	maxProfileNameBytes       = 32
	maxTargetTripleBytes      = 64
	maxTypeSignatureBytes     = 4096
	maxSizeVars               = 8
	maxSizeVarNameBytes       = 16
	maxCostBranches           = 16
	maxCostTerms              = 64
	maxCostTrials             = 16
	maxEmbeddedFormulaBytes   = 65536
	maxTrialSubjectBytes      = 65536
	maxProfileRefs            = 8
	maxObligationRefs         = 32
)

// Weft object kinds as named by the vector files.
const (
	KindNumericProfile  = "numeric_profile"
	KindCostCertificate = "cost_certificate"
	KindMeaningContract = "meaning_contract"
	KindJetCertificate  = "jet_certificate"
	KindSpanStatement   = "span_statement"
)

// Content-addressing domains (weft-v0.md §3).
var weftDomains = map[string]string{
	KindNumericProfile:  "NOOS/WEFT/PROFILE/V0",
	KindCostCertificate: "NOOS/WEFT/COST/V0",
	KindMeaningContract: "NOOS/WEFT/MEANING/V0",
	KindJetCertificate:  "NOOS/WEFT/JETCERT/V0",
	KindSpanStatement:   "NOOS/WEFT/SPAN/V0",
}

// WeftError is a frozen §6 rejection: stable numeric code + class.
type WeftError struct {
	Code  int
	Class string
}

func (e *WeftError) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Class) }

// weftDecodeError maps the codec's closed decode-error law onto the
// frozen §6 canonical images (codes 1–7; code 3 is reserved and
// unreachable in v0).
func weftDecodeError(err error) *WeftError {
	switch codec.ClassOf(err) {
	case codec.ErrTruncated:
		return &WeftError{1, "decode_truncated"}
	case codec.ErrTrailingBytes:
		return &WeftError{2, "decode_trailing_bytes"}
	case codec.ErrNonminimalAtom:
		return &WeftError{3, "decode_nonminimal_atom"}
	case codec.ErrUnknownMandatoryField:
		return &WeftError{4, "decode_unknown_field"}
	case codec.ErrLengthExceedsBound:
		return &WeftError{5, "decode_length_bound"}
	case codec.ErrUnknownVersion:
		return &WeftError{6, "decode_unknown_version"}
	case codec.ErrUnknownDiscriminant:
		return &WeftError{7, "decode_unknown_discriminant"}
	default:
		return &WeftError{4, "decode_unknown_field"}
	}
}

// DecodeWeftObject canonically decodes one v0 object of the named kind
// and returns its content id (H(domain || canonical bytes)). Unknown
// kinds reject with the frozen code 10. Decode errors carry the frozen
// §6 codes. Semantic (§5) checks are OUT of scope here — see the seam
// note above.
func DecodeWeftObject(kind string, b []byte) ([32]byte, error) {
	var zero [32]byte
	dom, ok := weftDomains[kind]
	if !ok {
		return zero, &WeftError{10, "unknown_object_kind"}
	}
	r := codec.NewReader(b)
	var err error
	switch kind {
	case KindNumericProfile:
		err = decodeNumericProfile(r)
	case KindCostCertificate:
		err = decodeCostCertificate(r)
	case KindMeaningContract:
		err = decodeMeaningContract(r)
	case KindJetCertificate:
		err = decodeJetCertificate(r)
	case KindSpanStatement:
		err = decodeSpanStatement(r)
	}
	if err == nil {
		err = r.Finish()
	}
	if err != nil {
		return zero, weftDecodeError(err)
	}
	return lumenref.DomainHash(dom, b), nil
}

// field runs one tagged decode step, short-circuiting on error.
type fieldRunner struct {
	r   *codec.Reader
	err error
}

func (f *fieldRunner) step(tag uint16, fn func() error) {
	if f.err != nil {
		return
	}
	if f.err = f.r.Tag(tag); f.err != nil {
		return
	}
	f.err = fn()
}

func decodeNumericProfile(r *codec.Reader) error {
	if err := r.Version(weftV0Version); err != nil {
		return err
	}
	f := &fieldRunner{r: r}
	f.step(1, func() (e error) { _, e = r.VarBytes(maxProfileNameBytes); return })
	f.step(2, func() (e error) { _, e = r.U8(); return })
	f.step(3, func() (e error) { _, e = r.U8(); return })
	f.step(4, func() (e error) { _, e = r.U8(); return })
	f.step(5, func() (e error) { _, e = r.U8(); return })
	f.step(6, func() (e error) { _, e = r.Discriminant(1); return }) // ROUND_HALF_UP_SHIFT
	f.step(7, func() (e error) { _, e = r.U32(); return })
	f.step(8, func() (e error) { _, e = r.U8(); return })
	f.step(9, func() (e error) { _, e = r.U8(); return })
	f.step(10, func() (e error) { _, e = r.U8(); return })
	f.step(11, func() (e error) { _, e = r.U32(); return })
	return f.err
}

func decodeCostCertificate(r *codec.Reader) error {
	if err := r.Version(weftV0Version); err != nil {
		return err
	}
	f := &fieldRunner{r: r}
	f.step(1, func() (e error) { _, e = r.Hash32(); return })
	f.step(2, func() (e error) { _, e = r.U32(); return })
	f.step(3, func() error { // size_vars
		n, e := r.ListLen(maxSizeVars, 4+8)
		if e != nil {
			return e
		}
		for range n {
			if _, e = r.VarBytes(maxSizeVarNameBytes); e != nil {
				return e
			}
			if _, e = r.U64(); e != nil {
				return e
			}
		}
		return nil
	})
	f.step(4, func() error { // branches
		n, e := r.ListLen(maxCostBranches, 4)
		if e != nil {
			return e
		}
		for range n {
			m, e := r.ListLen(maxCostTerms, 8+4)
			if e != nil {
				return e
			}
			for range m {
				if _, e = r.U64(); e != nil {
					return e
				}
				if _, e = r.VarBytes(maxSizeVars); e != nil {
					return e
				}
			}
		}
		return nil
	})
	f.step(5, func() (e error) { _, e = r.VarBytes(maxEmbeddedFormulaBytes); return })
	f.step(6, func() error { // trials
		n, e := r.ListLen(maxCostTrials, 4+4)
		if e != nil {
			return e
		}
		for range n {
			m, e := r.ListLen(maxSizeVars, 8)
			if e != nil {
				return e
			}
			for range m {
				if _, e = r.U64(); e != nil {
					return e
				}
			}
			if _, e = r.VarBytes(maxTrialSubjectBytes); e != nil {
				return e
			}
		}
		return nil
	})
	return f.err
}

func decodeMeaningContract(r *codec.Reader) error {
	if err := r.Version(weftV0Version); err != nil {
		return err
	}
	f := &fieldRunner{r: r}
	f.step(1, func() (e error) { _, e = r.Hash32(); return })
	f.step(2, func() (e error) { _, e = r.U32(); return })
	f.step(3, func() (e error) { _, e = r.Hash32(); return })
	f.step(4, func() (e error) { _, e = r.Hash32(); return })
	f.step(5, func() (e error) { _, e = r.VarBytes(maxTypeSignatureBytes); return })
	f.step(6, func() error {
		n, e := r.ListLen(maxProfileRefs, 32)
		if e != nil {
			return e
		}
		for range n {
			if _, e = r.Hash32(); e != nil {
				return e
			}
		}
		return nil
	})
	f.step(7, func() (e error) { _, e = r.Hash32(); return })
	f.step(8, func() (e error) { _, e = r.Hash32(); return })
	f.step(9, func() error {
		n, e := r.ListLen(maxObligationRefs, 32)
		if e != nil {
			return e
		}
		for range n {
			if _, e = r.Hash32(); e != nil {
				return e
			}
		}
		return nil
	})
	return f.err
}

func decodeJetCertificate(r *codec.Reader) error {
	if err := r.Version(weftV0Version); err != nil {
		return err
	}
	f := &fieldRunner{r: r}
	f.step(1, func() (e error) { _, e = r.U32(); return })
	f.step(2, func() (e error) { _, e = r.Hash32(); return })
	f.step(3, func() (e error) { _, e = r.Hash32(); return })
	f.step(4, func() (e error) { _, e = r.VarBytes(maxTargetTripleBytes); return })
	f.step(5, func() (e error) { _, e = r.Hash32(); return })
	f.step(6, func() (e error) { _, e = r.Hash32(); return })
	f.step(7, func() (e error) { _, e = r.Hash32(); return })
	f.step(8, func() (e error) { _, e = r.U64(); return })
	f.step(9, func() (e error) { _, e = r.Discriminant(6); return }) // status
	f.step(10, func() (e error) { _, e = r.U64(); return })
	f.step(11, func() (e error) { _, e = r.U64(); return })
	return f.err
}

func decodeSpanStatement(r *codec.Reader) error {
	if err := r.Version(weftV0Version); err != nil {
		return err
	}
	f := &fieldRunner{r: r}
	f.step(1, func() (e error) { _, e = r.Hash32(); return })
	f.step(2, func() (e error) { _, e = r.U32(); return })
	f.step(3, func() (e error) { _, e = r.U32(); return })
	f.step(4, func() (e error) { _, e = r.U32(); return })
	f.step(5, func() (e error) { _, e = r.Discriminant(1); return }) // SHA256_FLAT_V0
	f.step(6, func() (e error) { _, e = r.Discriminant(2); return }) // verifier_kind
	f.step(7, func() (e error) { _, e = r.Hash32(); return })
	f.step(8, func() (e error) { _, e = r.U16(); return })
	f.step(9, func() (e error) { _, e = r.U16(); return })
	f.step(10, func() (e error) { _, e = r.Discriminant(2); return }) // beacon_policy (1 decodes, checker rejects)
	f.step(11, func() (e error) { _, e = r.Discriminant(1); return }) // journal_schema
	return f.err
}
