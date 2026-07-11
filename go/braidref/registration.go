package braidref

import (
	"bytes"
	"crypto/ed25519"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Bond registration validity per witness-v1.md §1.1: possession proofs
// for BOTH keys — a BLS proof of possession over the consensus public key
// under the registered POP DST, and an Ed25519 self-signature by the
// withdrawal key under the "NOOS/SIG/TX/V1" context — plus the
// distinct-key-material law.

const sigTxCtx = "NOOS/SIG/TX/V1"

// BondErrorClass is a stable registration rejection class (the vector
// error_class literals).
type BondErrorClass string

const (
	BondKeyMaterialOverlap     BondErrorClass = "key_material_overlap"
	BondPossessionProofInvalid BondErrorClass = "possession_proof_invalid"
	BondSelfSignatureInvalid   BondErrorClass = "self_signature_invalid"
)

// BondError is a typed registration rejection.
type BondError struct{ Class BondErrorClass }

func (e *BondError) Error() string { return string(e.Class) }

// BondRegistrationV1 is the canonical registration envelope: version 1,
// tag 1 the canonical WitnessBond, tag 2 the 96-byte BLS proof of
// possession, tag 3 the 64-byte Ed25519 self-signature.
type BondRegistrationV1 struct {
	Bond                WitnessBond
	ProofOfPossession   [96]byte
	WithdrawalSignature [64]byte
}

// Encode returns the canonical bond bytes (the self-signature message
// tail).
func (b *WitnessBond) Encode() []byte {
	w := codec.NewWriter()
	w.Version(1)
	w.Tag(1)
	w.Hash32(b.ValidatorID)
	w.Tag(2)
	w.Fixed(b.ConsensusBLSKey[:])
	w.Tag(3)
	w.Hash32(b.WithdrawalKey)
	w.Tag(4)
	w.Hash32(b.NetworkEndpointsCommitment)
	w.Tag(5)
	w.VarBytes(b.FailureDomains)
	w.Tag(6)
	w.U128(b.BondedNoos)
	w.Tag(7)
	w.U64(b.ActivationEpoch)
	w.Tag(8)
	w.U64(b.ExitEpoch)
	w.Tag(9)
	w.Hash32(b.ProofpowerAccount)
	return w.Bytes()
}

// VerifyBondRegistration decodes and validates a canonical registration.
func VerifyBondRegistration(raw []byte) (*BondRegistrationV1, error) {
	r := codec.NewReader(raw)
	if err := r.Version(1); err != nil {
		return nil, err
	}
	if err := r.Tag(1); err != nil {
		return nil, err
	}
	bond, err := DecodeBondFields(r)
	if err != nil {
		return nil, err
	}
	reg := &BondRegistrationV1{Bond: bond}
	if err := r.Tag(2); err != nil {
		return nil, err
	}
	pop, err := r.Fixed(96)
	if err != nil {
		return nil, err
	}
	copy(reg.ProofOfPossession[:], pop)
	if err := r.Tag(3); err != nil {
		return nil, err
	}
	sig, err := r.Fixed(64)
	if err != nil {
		return nil, err
	}
	copy(reg.WithdrawalSignature[:], sig)
	if err := r.Finish(); err != nil {
		return nil, err
	}
	// Distinct-key-material law: the withdrawal key MUST differ from the
	// consensus key material (no 32-byte window of the BLS key may equal
	// it).
	if bytes.Contains(reg.Bond.ConsensusBLSKey[:], reg.Bond.WithdrawalKey[:]) {
		return nil, &BondError{Class: BondKeyMaterialOverlap}
	}
	// BLS proof of possession over the consensus public key bytes.
	if !BLSVerify(reg.Bond.ConsensusBLSKey, reg.Bond.ConsensusBLSKey[:], reg.ProofOfPossession, DSTPop) {
		return nil, &BondError{Class: BondPossessionProofInvalid}
	}
	// Ed25519 self-signature over the context-prefixed canonical bond.
	msg := append([]byte(sigTxCtx), reg.Bond.Encode()...)
	if !ed25519.Verify(reg.Bond.WithdrawalKey[:], msg, reg.WithdrawalSignature[:]) {
		return nil, &BondError{Class: BondSelfSignatureInvalid}
	}
	return reg, nil
}
