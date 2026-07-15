package lumenref

// Context-free protocol-v2 WWM action codec. It independently checks every
// fixed field, collection bound, object version/tag, closed payload tag, and
// whole-input consumption. Consensus payloads contain commitments and policy,
// never raw model, prompt, token-stream, or output bytes.

import (
	"encoding/binary"
	"fmt"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

const (
	WwmActionFirst    uint16 = 40
	WwmActionCount    uint16 = 60
	MaxTxWitnessBytes        = 65_532
)

type wire func(*codec.Reader) error

func fixed(n int) wire           { return func(r *codec.Reader) error { _, err := r.Fixed(n); return err } }
func u8(r *codec.Reader) error   { _, err := r.U8(); return err }
func u16(r *codec.Reader) error  { _, err := r.U16(); return err }
func u32(r *codec.Reader) error  { _, err := r.U32(); return err }
func u64(r *codec.Reader) error  { _, err := r.U64(); return err }
func u128(r *codec.Reader) error { _, err := r.U128(); return err }
func hash(r *codec.Reader) error { _, err := r.Hash32(); return err }
func varBytes(max uint32) wire {
	return func(r *codec.Reader) error { _, err := r.VarBytes(max); return err }
}
func enum8(count byte) wire {
	return func(r *codec.Reader) error {
		v, err := r.U8()
		if err != nil {
			return err
		}
		if v >= count {
			return &codec.Error{Class: codec.ErrUnknownDiscriminant, Context: fmt.Sprintf("discriminant %d, %d variants", v, count)}
		}
		return nil
	}
}
func optional(inner wire) wire {
	return func(r *codec.Reader) error {
		p, err := r.OptionalPresence()
		if err != nil {
			return err
		}
		if p {
			return inner(r)
		}
		return nil
	}
}
func list(max uint32, elem wire) wire {
	return func(r *codec.Reader) error {
		n, err := r.ListLen(max)
		if err != nil {
			return err
		}
		for i := uint32(0); i < n; i++ {
			if err := elem(r); err != nil {
				return err
			}
		}
		return nil
	}
}
func raw(parts ...wire) wire {
	return func(r *codec.Reader) error {
		for _, p := range parts {
			if err := p(r); err != nil {
				return err
			}
		}
		return nil
	}
}
func object(version uint16, fields ...wire) wire {
	return func(r *codec.Reader) error {
		if err := r.Version(version); err != nil {
			return err
		}
		for i, f := range fields {
			if err := r.Tag(uint16(i + 1)); err != nil {
				return err
			}
			if err := f(r); err != nil {
				return err
			}
		}
		return nil
	}
}

var (
	signature               = raw(hash, varBytes(96))
	signatures32            = list(32, signature)
	authority               = raw(u64, u64, varBytes(96))
	optHash                 = optional(hash)
	profile                 = object(1, hash, enum8(3), hash, hash, u32, hash, hash, u64, u64, u64, u64, hash)
	capabilityMutation wire = func(r *codec.Reader) error {
		tag, err := r.U8()
		if err != nil {
			return err
		}
		switch tag {
		case 0:
			return raw(profile, hash, authority)(r)
		case 1:
			return raw(hash, hash, enum8(3), enum8(3), authority)(r)
		default:
			return &codec.Error{Class: codec.ErrUnknownDiscriminant, Context: "capability mutation"}
		}
	}
	artifact                     = object(1, hash, u16, u64, hash, hash, hash, u16, u32, hash, hash, hash, hash, u64, signatures32)
	availabilityPolicy           = object(2, hash, hash, u8, u8, u8, u8, u8, u8, u8, u64, u64, u64, u64, u64)
	custodyCommitment            = object(2, hash, hash, u8, hash, hash, u64, u64, u64, varBytes(96))
	custodyChallenge             = object(2, hash, hash, hash, list(32, u32), u64, u64)
	custodyProbe                 = object(2, hash, hash, hash, u64, varBytes(96))
	availabilityCertificate      = object(2, hash, hash, hash, hash, u64, hash, u64, list(8, hash), list(5, hash), hash, u64, u64, list(5, signature))
	artifactRepair               = object(1, hash, hash, u8, hash, hash, hash, u64, varBytes(96))
	capsule                      = object(2, hash, hash, hash, hash, hash, hash, hash, hash, hash, hash, list(16, hash), hash, hash, hash, hash, hash, u8, optHash, u8, signatures32)
	executionProfile             = object(1, hash, hash, hash, hash, hash, u32, u32, u16, u16, u16, u8, u8, u8)
	feePolicy                    = object(1, hash, hash, u128, u128, u128, u128, hash, u64, varBytes(96))
	queryPolicy                  = object(1, hash, hash, u32, u32, u32, u64, u8, u8, u8, hash)
	serviceDirectory             = object(1, hash, u64, list(16, varBytes(512)), hash, hash, u64, u64, u64, signatures32)
	coverageRow                  = raw(enum8(5), u128, u128, u64, u64, u64, u128, u128)
	fundProfile                  = object(1, hash, hash, hash, hash, hash, list(5, coverageRow), u64, signatures32)
	fundMutationPayload     wire = func(r *codec.Reader) error {
		tag, err := r.U8()
		if err != nil {
			return err
		}
		switch tag {
		case 0:
			return raw(fundProfile, hash, authority)(r)
		case 1:
			return raw(enum8(2), hash, hash, u64, u64, u64, authority)(r)
		case 2:
			return raw(hash, hash, hash, hash, hash, u64, authority)(r)
		case 3:
			return raw(hash, hash, hash, hash, hash, authority)(r)
		default:
			return &codec.Error{Class: codec.ErrUnknownDiscriminant, Context: "fund mutation"}
		}
	}
	job              = object(1, hash, hash, hash, hash, u64, hash, hash, hash, hash, u32, u32, u64, list(3, hash), hash, hash, u128, hash)
	receipt          = object(1, hash, hash, hash, hash, hash, hash, hash, hash, hash, u32, u32, hash, hash, list(3, hash), list(3, hash), enum8(4), u64, u64, u64, hash, u128, u128, u128, enum8(5), list(3, signature))
	settlement       = object(1, hash, hash, hash, hash, enum8(5), u64, u128, u128, u128, u64, u64, varBytes(96))
	aliasTransition  = object(1, hash, varBytes(64), optHash, optHash, hash, enum8(5), u64, u64, varBytes(96))
	authorizedConfig wire
	reconfiguration  wire
	recovery         wire
	activation       wire
	controlPayload   wire
)

func init() {
	authorizedConfig = object(1, hash, optHash, enum8(5), hash, hash, hash, hash, hash, hash, hash, hash, hash, list(32, hash), list(32, hash), varBytes(1024), hash, varBytes(10240), hash, hash, hash, hash, u64, u64, signatures32)
	reconfiguration = object(1, hash, hash, hash, hash, hash, hash, u64, hash, authorizedConfig, optional(feePolicy), optional(serviceDirectory), list(8, profile), u8, u64, u64, u64, u64, optHash, u64, signatures32)
	recovery = object(1, hash, enum8(5), hash, hash, hash, hash, hash, hash, hash, hash, u64, u64, u64, u64, u64, signatures32)
	activation = object(1, hash, enum8(5), enum8(5), optHash, hash, u64, u64, u64, signatures32)
	controlPayload = func(r *codec.Reader) error {
		tag, err := r.U8()
		if err != nil {
			return err
		}
		switch tag {
		case 0:
			return raw(activation, authorizedConfig)(r)
		case 1:
			return raw(enum8(5), optHash, hash, authority)(r)
		case 2:
			return reconfiguration(r)
		case 3:
			return raw(hash, hash)(r)
		case 4:
			return recovery(r)
		default:
			return &codec.Error{Class: codec.ErrUnknownDiscriminant, Context: "control transition"}
		}
	}
}

func wwmSchema(discriminant uint16) (wire, bool) {
	schemas := [...]wire{artifact, capabilityMutation, availabilityPolicy, custodyCommitment, custodyChallenge, custodyProbe, availabilityCertificate, artifactRepair, capsule, executionProfile, capabilityMutation, feePolicy, fundMutationPayload, queryPolicy, serviceDirectory, job, receipt, settlement, aliasTransition, controlPayload}
	if discriminant < WwmActionFirst || discriminant >= WwmActionCount {
		return nil, false
	}
	return schemas[discriminant-WwmActionFirst], true
}

// WwmActionV1 preserves the byte-identical typed payload after validating its
// complete schema. Discriminant is declaration-order u16, matching Rust.
type WwmActionV1 struct {
	Discriminant uint16
	Payload      []byte
}

func DecodeWwmAction(b []byte) (*WwmActionV1, error) {
	if len(b) < 2 {
		return nil, &codec.Error{Class: codec.ErrTruncated, Context: "WWM action discriminant"}
	}
	discriminant := binary.LittleEndian.Uint16(b[:2])
	schema, ok := wwmSchema(discriminant)
	if !ok {
		return nil, &codec.Error{Class: codec.ErrUnknownDiscriminant, Context: fmt.Sprintf("action %d", discriminant)}
	}
	payload := append([]byte(nil), b[2:]...)
	r := codec.NewReader(payload)
	if err := schema(r); err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return &WwmActionV1{Discriminant: discriminant, Payload: payload}, nil
}

func (a *WwmActionV1) Encode() ([]byte, error) {
	schema, ok := wwmSchema(a.Discriminant)
	if !ok {
		return nil, &codec.Error{Class: codec.ErrUnknownDiscriminant, Context: "WWM action"}
	}
	r := codec.NewReader(a.Payload)
	if err := schema(r); err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	out := make([]byte, 2, len(a.Payload)+2)
	binary.LittleEndian.PutUint16(out, a.Discriminant)
	out = append(out, a.Payload...)
	return out, nil
}

// CarrierLenValid enforces tx_bytes+witness_bytes<=65,532; TxPush's four-byte
// transaction-length prefix then fits the unchanged 65,536-byte carrier.
func CarrierLenValid(txBytes, witnessBytes int) bool {
	return txBytes >= 0 && witnessBytes >= 0 && txBytes <= MaxTxWitnessBytes && witnessBytes <= MaxTxWitnessBytes-txBytes
}
