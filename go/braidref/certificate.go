package braidref

import (
	"math/big"

	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Finality votes and aggregate certificates per protocol/schemas/
// witness-v1.md §§1.2–1.3 and plan §6.6.

const (
	// MaxParticipationBitmapBytes covers N_hard = 1024 bits.
	MaxParticipationBitmapBytes = 128

	witnessCertDigestCtx = "NOOS/WITNESS/CERT/DIGEST/V1"
)

// FinalityVote is the per-witness checkpoint vote (witness-v1.md §1.2).
type FinalityVote struct {
	ChainID        [32]byte
	Epoch          uint64
	Source         CheckpointRef
	Target         CheckpointRef
	ValidatorID    [32]byte
	MembershipRoot [32]byte
	Signature      [96]byte
}

func decodeVoteFields(r *codec.Reader) (FinalityVote, error) {
	var v FinalityVote
	var err error
	if err = r.Version(1); err != nil {
		return v, err
	}
	step := func(tag uint16, f func() error) {
		if err != nil {
			return
		}
		if err = r.Tag(tag); err != nil {
			return
		}
		err = f()
	}
	step(1, func() (e error) { v.ChainID, e = r.Hash32(); return })
	step(2, func() (e error) { v.Epoch, e = r.U64(); return })
	step(3, func() (e error) { v.Source, e = decodeCheckpointRef(r); return })
	step(4, func() (e error) { v.Target, e = decodeCheckpointRef(r); return })
	step(5, func() (e error) { v.ValidatorID, e = r.Hash32(); return })
	step(6, func() (e error) { v.MembershipRoot, e = r.Hash32(); return })
	step(7, func() error {
		raw, e := r.Fixed(96)
		if e != nil {
			return e
		}
		copy(v.Signature[:], raw)
		return nil
	})
	return v, err
}

// DecodeVote decodes a canonical FinalityVote (whole input).
func DecodeVote(b []byte) (*FinalityVote, error) {
	r := codec.NewReader(b)
	v, err := decodeVoteFields(r)
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return &v, nil
}

// SigningBytes is the canonical vote body: fields 0–5 (version and tags
// 1..6, signature excluded).
func (v *FinalityVote) SigningBytes() []byte {
	w := codec.NewWriter()
	v.encodeBody(w)
	return w.Bytes()
}

func (v *FinalityVote) encodeBody(w *codec.Writer) {
	w.Version(1)
	w.Tag(1)
	w.Hash32(v.ChainID)
	w.Tag(2)
	w.U64(v.Epoch)
	w.Tag(3)
	v.Source.encode(w)
	w.Tag(4)
	v.Target.encode(w)
	w.Tag(5)
	w.Hash32(v.ValidatorID)
	w.Tag(6)
	w.Hash32(v.MembershipRoot)
}

// Encode returns the full canonical vote bytes.
func (v *FinalityVote) Encode() []byte {
	w := codec.NewWriter()
	v.encodeBody(w)
	w.Tag(7)
	w.Fixed(v.Signature[:])
	return w.Bytes()
}

// VoteErrorClass is a stable vote-verification rejection class (the vector
// error_class literals).
type VoteErrorClass string

const (
	VoteUnknownValidator       VoteErrorClass = "unknown_validator"
	VoteMembershipRootMismatch VoteErrorClass = "membership_root_mismatch"
	VoteSignatureInvalid       VoteErrorClass = "signature_invalid"
)

// VoteError is a typed vote rejection.
type VoteError struct{ Class VoteErrorClass }

func (e *VoteError) Error() string { return string(e.Class) }

// VerifyVote checks a decoded vote against the epoch snapshot: the voter
// must be a snapshot member, the membership root must equal the snapshot
// root, and the BLS signature must verify over the canonical vote body
// under the registered vote DST.
func VerifyVote(v *FinalityVote, snap *Snapshot) error {
	m := snap.MemberByID(v.ValidatorID)
	if m == nil {
		return &VoteError{Class: VoteUnknownValidator}
	}
	if v.MembershipRoot != snap.Root() {
		return &VoteError{Class: VoteMembershipRootMismatch}
	}
	if !BLSVerify(m.BLSKey, v.SigningBytes(), v.Signature, DSTVote) {
		return &VoteError{Class: VoteSignatureInvalid}
	}
	return nil
}

// FinalityCertificateV1 is the aggregate certificate (witness-v1.md §1.3).
type FinalityCertificateV1 struct {
	Source              CheckpointRef
	Target              CheckpointRef
	ParticipationBitmap []byte
	AggregateSignature  [96]byte
	RawWeightSum        codec.U128
	EffectiveWeightSum  codec.U128
	MembershipRoot      [32]byte
}

func decodeCertificateFields(r *codec.Reader) (FinalityCertificateV1, error) {
	var c FinalityCertificateV1
	var err error
	if err = r.Version(1); err != nil {
		return c, err
	}
	step := func(tag uint16, f func() error) {
		if err != nil {
			return
		}
		if err = r.Tag(tag); err != nil {
			return
		}
		err = f()
	}
	step(1, func() (e error) { c.Source, e = decodeCheckpointRef(r); return })
	step(2, func() (e error) { c.Target, e = decodeCheckpointRef(r); return })
	step(3, func() (e error) { c.ParticipationBitmap, e = r.VarBytes(MaxParticipationBitmapBytes); return })
	step(4, func() error {
		raw, e := r.Fixed(96)
		if e != nil {
			return e
		}
		copy(c.AggregateSignature[:], raw)
		return nil
	})
	step(5, func() (e error) { c.RawWeightSum, e = r.U128(); return })
	step(6, func() (e error) { c.EffectiveWeightSum, e = r.U128(); return })
	step(7, func() (e error) { c.MembershipRoot, e = r.Hash32(); return })
	return c, err
}

// DecodeCertificate decodes a canonical FinalityCertificateV1 (whole
// input).
func DecodeCertificate(b []byte) (*FinalityCertificateV1, error) {
	r := codec.NewReader(b)
	c, err := decodeCertificateFields(r)
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Encode returns the canonical certificate bytes.
func (c *FinalityCertificateV1) Encode() []byte {
	w := codec.NewWriter()
	w.Version(1)
	w.Tag(1)
	c.Source.encode(w)
	w.Tag(2)
	c.Target.encode(w)
	w.Tag(3)
	w.VarBytes(c.ParticipationBitmap)
	w.Tag(4)
	w.Fixed(c.AggregateSignature[:])
	w.Tag(5)
	w.U128(c.RawWeightSum)
	w.Tag(6)
	w.U128(c.EffectiveWeightSum)
	w.Tag(7)
	w.Hash32(c.MembershipRoot)
	return w.Bytes()
}

// Digest is the D-WITNESS-CERT-DIGEST content digest used for the
// duplicate-ingest short circuit.
func (c *FinalityCertificateV1) Digest() [32]byte {
	return lumenref.DomainHash(witnessCertDigestCtx, c.Encode())
}

// SignerIndices expands the participation bitmap under the frozen
// LSB-first bit order (constants-v1.toml [witness] bitmap_bit_order):
// bit i of member i = byte[i/8] >> (i%8) & 1; length exactly ceil(n/8).
func (c *FinalityCertificateV1) SignerIndices(memberCount int) ([]int, error) {
	wantLen := (memberCount + 7) / 8
	if len(c.ParticipationBitmap) != wantLen {
		return nil, &CertError{Class: CertBitmapOutOfRange}
	}
	var idx []int
	for i, b := range c.ParticipationBitmap {
		for bit := range 8 {
			if b>>bit&1 == 1 {
				pos := i*8 + bit
				if pos >= memberCount {
					return nil, &CertError{Class: CertBitmapOutOfRange}
				}
				idx = append(idx, pos)
			}
		}
	}
	return idx, nil
}

// CertErrorClass is a stable certificate rejection class (the vector
// error_class literals).
type CertErrorClass string

const (
	CertBitmapOutOfRange      CertErrorClass = "bitmap_out_of_range"
	CertEmptySignerSet        CertErrorClass = "empty_signer_set"
	CertMembershipMismatch    CertErrorClass = "membership_root_mismatch"
	CertWeightSumMismatch     CertErrorClass = "weight_sum_mismatch"
	CertAggregateInvalid      CertErrorClass = "aggregate_invalid"
)

// CertError is a typed certificate rejection.
type CertError struct{ Class CertErrorClass }

func (e *CertError) Error() string { return string(e.Class) }

// VerifyCertificate checks a decoded certificate against the epoch
// snapshot in the frozen order:
//
//  1. bitmap length/range (bitmap_out_of_range),
//  2. nonempty signer set (empty_signer_set),
//  3. membership root binding (membership_root_mismatch),
//  4. BOTH weight sums recomputed from the snapshot — carried sums are
//     never trusted (weight_sum_mismatch),
//  5. the aggregate signature over the per-signer canonical vote bodies
//     under the registered vote DST (aggregate_invalid). A certificate
//     aggregates the member votes themselves: each signer's message is
//     the FinalityVote body (chainID, epoch = vote epoch, source, target,
//     validator_id, membership_root).
//
// It does NOT decide justification: callers compare the verified sums
// against JustificationThreshold on raw and effective weight separately.
func VerifyCertificate(c *FinalityCertificateV1, snap *Snapshot, chainID [32]byte, voteEpoch uint64) error {
	signers, err := c.SignerIndices(len(snap.Members))
	if err != nil {
		return err
	}
	if len(signers) == 0 {
		return &CertError{Class: CertEmptySignerSet}
	}
	if c.MembershipRoot != snap.Root() {
		return &CertError{Class: CertMembershipMismatch}
	}
	raw := c.RawWeightSum.Big()
	eff := c.EffectiveWeightSum.Big()
	wantRaw := new(big.Int)
	wantEff := new(big.Int)
	for _, i := range signers {
		wantRaw.Add(wantRaw, snap.Members[i].Raw)
		wantEff.Add(wantEff, snap.Members[i].Effective)
	}
	if raw.Cmp(wantRaw) != 0 || eff.Cmp(wantEff) != 0 {
		return &CertError{Class: CertWeightSumMismatch}
	}
	pubkeys := make([][48]byte, 0, len(signers))
	msgs := make([][]byte, 0, len(signers))
	for _, i := range signers {
		m := &snap.Members[i]
		vote := FinalityVote{
			ChainID:        chainID,
			Epoch:          voteEpoch,
			Source:         c.Source,
			Target:         c.Target,
			ValidatorID:    m.ValidatorID,
			MembershipRoot: c.MembershipRoot,
		}
		pubkeys = append(pubkeys, m.BLSKey)
		msgs = append(msgs, vote.SigningBytes())
	}
	if !BLSVerifyDistinct(pubkeys, msgs, c.AggregateSignature, DSTVote) {
		return &CertError{Class: CertAggregateInvalid}
	}
	return nil
}
