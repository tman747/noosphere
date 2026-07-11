package braidref

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// BLS12-381 verification per protocol/spec/crypto-domains-v1.csv: public
// keys are 48-byte compressed G1 (min-pk shape of the header/bond tables),
// signatures 96-byte compressed G2, hashed to G2 with XMD:SHA-256_SSWU_RO
// under the registered NOOS DSTs.

const (
	// DSTVote is the registered D-BLS-VOTE domain separation tag.
	DSTVote = "NOOS-BLS-VOTE-V1_BLS12381G2_XMD:SHA-256_SSWU_RO_"
	// DSTCert is the registered D-BLS-CERT domain separation tag.
	DSTCert = "NOOS-BLS-CERT-V1_BLS12381G2_XMD:SHA-256_SSWU_RO_"
	// DSTPop is the registered D-BLS-POP domain separation tag.
	DSTPop = "NOOS-BLS-POP-V1_BLS12381G2_XMD:SHA-256_SSWU_RO_"
	// DSTProposer is the registered D-BLS-PROPOSER domain separation tag.
	DSTProposer = "NOOS-BLS-PROPOSER-V1_BLS12381G2_XMD:SHA-256_SSWU_RO_"
)

var negG1Gen bls12381.G1Affine

func init() {
	_, _, g1, _ := bls12381.Generators()
	negG1Gen.Neg(&g1)
}

func decodePubkey(pk [48]byte) (bls12381.G1Affine, error) {
	var p bls12381.G1Affine
	if _, err := p.SetBytes(pk[:]); err != nil {
		return p, fmt.Errorf("bls pubkey: %w", err)
	}
	if p.IsInfinity() {
		return p, fmt.Errorf("bls pubkey: infinity")
	}
	return p, nil
}

func decodeSignature(sig [96]byte) (bls12381.G2Affine, error) {
	var s bls12381.G2Affine
	if _, err := s.SetBytes(sig[:]); err != nil {
		return s, fmt.Errorf("bls signature: %w", err)
	}
	return s, nil
}

// BLSVerify checks one signature over one message:
// e(pk, H(msg)) == e(g1, sig).
func BLSVerify(pubkey [48]byte, msg []byte, sig [96]byte, dst string) bool {
	return BLSVerifyDistinct([][48]byte{pubkey}, [][]byte{msg}, sig, dst)
}

// BLSVerifyDistinct checks an aggregate signature over per-signer messages:
// prod_i e(pk_i, H(msg_i)) * e(-g1, sig) == 1.
func BLSVerifyDistinct(pubkeys [][48]byte, msgs [][]byte, sig [96]byte, dst string) bool {
	if len(pubkeys) != len(msgs) || len(pubkeys) == 0 {
		return false
	}
	s, err := decodeSignature(sig)
	if err != nil {
		return false
	}
	ps := make([]bls12381.G1Affine, 0, len(pubkeys)+1)
	qs := make([]bls12381.G2Affine, 0, len(pubkeys)+1)
	for i, pk := range pubkeys {
		p, err := decodePubkey(pk)
		if err != nil {
			return false
		}
		h, err := bls12381.HashToG2(msgs[i], []byte(dst))
		if err != nil {
			return false
		}
		ps = append(ps, p)
		qs = append(qs, h)
	}
	ps = append(ps, negG1Gen)
	qs = append(qs, s)
	ok, err := bls12381.PairingCheck(ps, qs)
	return err == nil && ok
}
