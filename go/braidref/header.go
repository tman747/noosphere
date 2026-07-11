package braidref

import (
	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// BlockHeaderV1 wire law per protocol/spec/schema-tables/header-body.md:
// the leading canonical u16 object version IS field #1 (version); the
// remaining 29 fields follow as tag:u16 LE || value pairs in exact table
// order with tags 1..=29.

const (
	blockHeaderCtx        = "NOOS/BLOCK/HEADER/V1"
	proposalCommitmentCtx = "NOOS/BLOCK/PROPOSAL/V1"

	// HeaderVersion is the only header version this package decodes.
	HeaderVersion uint16 = 1
	// GroundProfileIDV1 is the mandatory ground profile under Braid v1.
	GroundProfileIDV1 uint32 = 1
)

// CheckpointRef is {epoch u64, checkpoint_hash Hash32}
// (header-body.md CheckpointRef; witness-v1.md names the same shape
// {height, hash} for votes).
type CheckpointRef struct {
	Epoch uint64
	Hash  [32]byte
}

func decodeCheckpointRef(r *codec.Reader) (CheckpointRef, error) {
	var c CheckpointRef
	var err error
	if c.Epoch, err = r.U64(); err != nil {
		return c, err
	}
	c.Hash, err = r.Hash32()
	return c, err
}

func (c CheckpointRef) encode(w *codec.Writer) {
	w.U64(c.Epoch)
	w.Hash32(c.Hash)
}

// ResourceVector5 carries the five priced axes B,G,V,R,D.
type ResourceVector5 [5]uint64

func decodeResourceVector5(r *codec.Reader) (ResourceVector5, error) {
	var v ResourceVector5
	for i := range v {
		u, err := r.U64()
		if err != nil {
			return v, err
		}
		v[i] = u
	}
	return v, nil
}

func (v ResourceVector5) encode(w *codec.Writer) {
	for _, u := range v {
		w.U64(u)
	}
}

// BlockHeaderV1 is the canonical block header (header-body.md table).
type BlockHeaderV1 struct {
	ChainID                 [32]byte // tag 1
	Height                  uint64   // tag 2
	Slot                    uint64   // tag 3
	TimestampMS             uint64   // tag 4
	ParentHash              [32]byte // tag 5
	ProposerKey             [48]byte // tag 6
	TxRoot                  [32]byte // tag 7
	WitnessRoot             [32]byte // tag 8
	ExecutionReceiptRoot    [32]byte // tag 9
	EvidenceRoot            [32]byte // tag 10
	BodyDARoot              [32]byte // tag 11
	NotesRoot               [32]byte // tag 12
	NullifiersRoot          [32]byte // tag 13
	AccountsRoot            [32]byte // tag 14
	ObjectsRoot             [32]byte // tag 15
	LumenReceiptsStateRoot  [32]byte // tag 16
	ParamsRoot              [32]byte // tag 17
	JustifiedCheckpoint     CheckpointRef
	FinalizedCheckpoint     CheckpointRef
	FinalityCertificateRoot [32]byte // tag 20
	WitnessMembershipRoot   [32]byte // tag 21
	GroundProfileID         uint32   // tag 22
	GroundTargetLE          [32]byte // tag 23, u256 little-endian
	GroundTicketRoot        [32]byte // tag 24
	LoomCreditRoot          [32]byte // tag 25
	LoomCredit              codec.U128
	GasUsed                 ResourceVector5 // tag 27
	BasePrices              ResourceVector5 // tag 28
	ProposerSignature       [96]byte        // tag 29
}

// DecodeHeader decodes a canonical BlockHeaderV1 (whole input).
func DecodeHeader(b []byte) (*BlockHeaderV1, error) {
	r := codec.NewReader(b)
	h, err := decodeHeaderFields(r)
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return h, nil
}

func decodeHeaderFields(r *codec.Reader) (*BlockHeaderV1, error) {
	h := &BlockHeaderV1{}
	var err error
	if err = r.Version(HeaderVersion); err != nil {
		return nil, err
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
	hash := func(dst *[32]byte) func() error {
		return func() (e error) { *dst, e = r.Hash32(); return }
	}
	step(1, hash(&h.ChainID))
	step(2, func() (e error) { h.Height, e = r.U64(); return })
	step(3, func() (e error) { h.Slot, e = r.U64(); return })
	step(4, func() (e error) { h.TimestampMS, e = r.U64(); return })
	step(5, hash(&h.ParentHash))
	step(6, func() error {
		b, e := r.Fixed(48)
		if e != nil {
			return e
		}
		copy(h.ProposerKey[:], b)
		return nil
	})
	step(7, hash(&h.TxRoot))
	step(8, hash(&h.WitnessRoot))
	step(9, hash(&h.ExecutionReceiptRoot))
	step(10, hash(&h.EvidenceRoot))
	step(11, hash(&h.BodyDARoot))
	step(12, hash(&h.NotesRoot))
	step(13, hash(&h.NullifiersRoot))
	step(14, hash(&h.AccountsRoot))
	step(15, hash(&h.ObjectsRoot))
	step(16, hash(&h.LumenReceiptsStateRoot))
	step(17, hash(&h.ParamsRoot))
	step(18, func() (e error) { h.JustifiedCheckpoint, e = decodeCheckpointRef(r); return })
	step(19, func() (e error) { h.FinalizedCheckpoint, e = decodeCheckpointRef(r); return })
	step(20, hash(&h.FinalityCertificateRoot))
	step(21, hash(&h.WitnessMembershipRoot))
	step(22, func() (e error) { h.GroundProfileID, e = r.U32(); return })
	step(23, hash(&h.GroundTargetLE))
	step(24, hash(&h.GroundTicketRoot))
	step(25, hash(&h.LoomCreditRoot))
	step(26, func() (e error) { h.LoomCredit, e = r.U128(); return })
	step(27, func() (e error) { h.GasUsed, e = decodeResourceVector5(r); return })
	step(28, func() (e error) { h.BasePrices, e = decodeResourceVector5(r); return })
	step(29, func() error {
		b, e := r.Fixed(96)
		if e != nil {
			return e
		}
		copy(h.ProposerSignature[:], b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// encodeField writes one tagged field payload; used by both Encode and the
// proposal-commitment preimage (which drops tags 24 and 29).
func (h *BlockHeaderV1) encodeField(w *codec.Writer, tag uint16) {
	w.Tag(tag)
	switch tag {
	case 1:
		w.Hash32(h.ChainID)
	case 2:
		w.U64(h.Height)
	case 3:
		w.U64(h.Slot)
	case 4:
		w.U64(h.TimestampMS)
	case 5:
		w.Hash32(h.ParentHash)
	case 6:
		w.Fixed(h.ProposerKey[:])
	case 7:
		w.Hash32(h.TxRoot)
	case 8:
		w.Hash32(h.WitnessRoot)
	case 9:
		w.Hash32(h.ExecutionReceiptRoot)
	case 10:
		w.Hash32(h.EvidenceRoot)
	case 11:
		w.Hash32(h.BodyDARoot)
	case 12:
		w.Hash32(h.NotesRoot)
	case 13:
		w.Hash32(h.NullifiersRoot)
	case 14:
		w.Hash32(h.AccountsRoot)
	case 15:
		w.Hash32(h.ObjectsRoot)
	case 16:
		w.Hash32(h.LumenReceiptsStateRoot)
	case 17:
		w.Hash32(h.ParamsRoot)
	case 18:
		h.JustifiedCheckpoint.encode(w)
	case 19:
		h.FinalizedCheckpoint.encode(w)
	case 20:
		w.Hash32(h.FinalityCertificateRoot)
	case 21:
		w.Hash32(h.WitnessMembershipRoot)
	case 22:
		w.U32(h.GroundProfileID)
	case 23:
		w.Hash32(h.GroundTargetLE)
	case 24:
		w.Hash32(h.GroundTicketRoot)
	case 25:
		w.Hash32(h.LoomCreditRoot)
	case 26:
		w.U128(h.LoomCredit)
	case 27:
		h.GasUsed.encode(w)
	case 28:
		h.BasePrices.encode(w)
	case 29:
		w.Fixed(h.ProposerSignature[:])
	}
}

// Encode returns the canonical header bytes.
func (h *BlockHeaderV1) Encode() []byte {
	w := codec.NewWriter()
	w.Version(HeaderVersion)
	for tag := uint16(1); tag <= 29; tag++ {
		h.encodeField(w, tag)
	}
	return w.Bytes()
}

// BlockHash is the D-BLOCK-HEADER law: BLAKE3-256("NOOS/BLOCK/HEADER/V1" ||
// canonical header) over the FULL encoding including proposer_signature.
func (h *BlockHeaderV1) BlockHash() [32]byte {
	return lumenref.DomainHash(blockHeaderCtx, h.Encode())
}

// ProposalCommitment is the D-PROPOSAL-COMMITMENT law: BLAKE3-256(
// "NOOS/BLOCK/PROPOSAL/V1" || version_u16_le || (tag_u16_le || canonical
// bytes) for every field in tag order EXCEPT tags 24 (ground_ticket_root)
// and 29 (proposer_signature)).
func (h *BlockHeaderV1) ProposalCommitment() [32]byte {
	w := codec.NewWriter()
	w.Version(HeaderVersion)
	for tag := uint16(1); tag <= 29; tag++ {
		if tag == 24 || tag == 29 {
			continue
		}
		h.encodeField(w, tag)
	}
	return lumenref.DomainHash(proposalCommitmentCtx, w.Bytes())
}
