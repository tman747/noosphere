package braidref

import (
	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// BlockBodyV1 per protocol/spec/schema-tables/header-body.md: version 1,
// tags 1..7 = transactions, segregated_witnesses, system_transitions,
// finality_certificates, ground_ticket (exactly one, 76 bytes),
// loom_credit_claims (max 0 while the lane is disabled — a nonzero count
// is a decode-level length_exceeds_bound), consensus_blob_descriptors.

// Frozen body collection maxima (header-body.md, PROPOSED-G0).
const (
	MaxBodyTransactions      = 16384
	MaxBodyWitnesses         = 16384
	MaxBodySystemTransitions = 256
	MaxBodyCertificates      = 8
	MaxBodyLoomClaims        = 0
	MaxBodyBlobDescriptors   = 64
	// MaxSystemTransitionBytes bounds one typed system-transition blob
	// (engineering bound; the frozen tables bound the count, not the
	// element, and the vectors exercise only small elements).
	MaxSystemTransitionBytes = 65536
)

// BlobDescriptor per protocol/spec/schema-tables/da.md (version 1,
// tags 1..10; the two optionals carry presence bytes).
type BlobDescriptor struct {
	Namespace            uint32
	ContentRoot          [32]byte
	OriginalBytes        uint64
	ShardBytes           uint32
	DataShards           uint16
	ParityShards         uint16
	RetentionEpochs      uint32
	CodecID              uint16
	EncryptionDescriptor []byte // nil = absent
	AccessPolicyRoot     *[32]byte
}

const maxEncryptionDescriptorBytes = 256

func decodeBlobDescriptor(r *codec.Reader) (BlobDescriptor, error) {
	var d BlobDescriptor
	var err error
	if err = r.Version(1); err != nil {
		return d, err
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
	step(1, func() (e error) { d.Namespace, e = r.U32(); return })
	step(2, func() (e error) { d.ContentRoot, e = r.Hash32(); return })
	step(3, func() (e error) { d.OriginalBytes, e = r.U64(); return })
	step(4, func() (e error) { d.ShardBytes, e = r.U32(); return })
	step(5, func() (e error) { d.DataShards, e = r.U16(); return })
	step(6, func() (e error) { d.ParityShards, e = r.U16(); return })
	step(7, func() (e error) { d.RetentionEpochs, e = r.U32(); return })
	step(8, func() (e error) { d.CodecID, e = r.U16(); return })
	step(9, func() error {
		present, e := r.OptionalPresence()
		if e != nil || !present {
			return e
		}
		d.EncryptionDescriptor, e = r.VarBytes(maxEncryptionDescriptorBytes)
		return e
	})
	step(10, func() error {
		present, e := r.OptionalPresence()
		if e != nil || !present {
			return e
		}
		h, e := r.Hash32()
		if e != nil {
			return e
		}
		d.AccessPolicyRoot = &h
		return nil
	})
	return d, err
}

// BlockBodyV1 is the decoded block body. Transactions and witnesses are
// decoded through the lumenref envelope law.
type BlockBodyV1 struct {
	Transactions         []*lumenref.TransactionV1
	SegregatedWitnesses  []*lumenref.TransactionWitnessesV1
	SystemTransitions    [][]byte
	FinalityCertificates []FinalityCertificateV1
	GroundTicket         GroundTicketV1
	BlobDescriptors      []BlobDescriptor
}

// DecodeBody decodes a canonical BlockBodyV1 (whole input).
func DecodeBody(b []byte) (*BlockBodyV1, error) {
	r := codec.NewReader(b)
	body := &BlockBodyV1{}
	if err := r.Version(1); err != nil {
		return nil, err
	}
	if err := r.Tag(1); err != nil {
		return nil, err
	}
	n, err := r.ListLen(MaxBodyTransactions)
	if err != nil {
		return nil, err
	}
	for range n {
		tx, err := lumenref.DecodeTransactionFrom(r)
		if err != nil {
			return nil, err
		}
		body.Transactions = append(body.Transactions, tx)
	}
	if err := r.Tag(2); err != nil {
		return nil, err
	}
	if n, err = r.ListLen(MaxBodyWitnesses); err != nil {
		return nil, err
	}
	for range n {
		tw, err := lumenref.DecodeWitnessesFrom(r)
		if err != nil {
			return nil, err
		}
		body.SegregatedWitnesses = append(body.SegregatedWitnesses, tw)
	}
	if err := r.Tag(3); err != nil {
		return nil, err
	}
	if n, err = r.ListLen(MaxBodySystemTransitions); err != nil {
		return nil, err
	}
	for range n {
		st, err := r.VarBytes(MaxSystemTransitionBytes)
		if err != nil {
			return nil, err
		}
		body.SystemTransitions = append(body.SystemTransitions, st)
	}
	if err := r.Tag(4); err != nil {
		return nil, err
	}
	if n, err = r.ListLen(MaxBodyCertificates); err != nil {
		return nil, err
	}
	for range n {
		c, err := decodeCertificateFields(r)
		if err != nil {
			return nil, err
		}
		body.FinalityCertificates = append(body.FinalityCertificates, c)
	}
	if err := r.Tag(5); err != nil {
		return nil, err
	}
	if body.GroundTicket, err = decodeTicketFields(r); err != nil {
		return nil, err
	}
	if err := r.Tag(6); err != nil {
		return nil, err
	}
	if _, err = r.ListLen(MaxBodyLoomClaims); err != nil {
		return nil, err
	}
	if err := r.Tag(7); err != nil {
		return nil, err
	}
	if n, err = r.ListLen(MaxBodyBlobDescriptors); err != nil {
		return nil, err
	}
	for range n {
		d, err := decodeBlobDescriptor(r)
		if err != nil {
			return nil, err
		}
		body.BlobDescriptors = append(body.BlobDescriptors, d)
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return body, nil
}
