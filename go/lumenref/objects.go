package lumenref

import (
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Canonical Lumen object shapes per protocol/spec/schema-tables/
// lumen-objects.md and protocol/schemas/lumen-v1.md. Encoding law: u16
// little-endian object version (= 1), then per field in declaration order a
// u16 mandatory tag (sequential from 1) followed by the field's canonical
// encoding; optional fields carry a one-byte presence flag.

// Frozen collection maxima (lumen-objects.md §5, lumen-v1.md §4.2).
const (
	MaxNoteInputs      = 256
	MaxAccountInputs   = 64
	MaxObjectAccess    = 256
	MaxActions         = 64
	MaxActionBytes     = 65536
	MaxOutputs         = 256
	MaxEvidenceRefs    = 64
	MaxIntents         = 64
	MaxLockReveals     = 256
	MaxLockRevealBytes = 4096
	MaxSignatureBytes  = 96
)

// ResourceVector6 is the six-axis declared resource vector
// {bytes, grain_steps, proof_units, state_reads, state_writes, blob_bytes}.
type ResourceVector6 [6]uint64

func decodeResourceVector6(r *codec.Reader) (ResourceVector6, error) {
	var v ResourceVector6
	for i := range v {
		u, err := r.U64()
		if err != nil {
			return v, err
		}
		v[i] = u
	}
	return v, nil
}

func (v ResourceVector6) encode(w *codec.Writer) {
	for _, u := range v {
		w.U64(u)
	}
}

// NoteV1 is the immutable public note (lumen-objects.md §2).
type NoteV1 struct {
	AssetID          [32]byte
	Amount           codec.U128
	LockRoot         [32]byte
	DatumRoot        [32]byte
	BirthHeight      uint64
	RelativeTimelock uint32
	MemoCommitment   [32]byte
}

func decodeNoteFields(r *codec.Reader) (NoteV1, error) {
	var n NoteV1
	var err error
	if err = r.Version(1); err != nil {
		return n, err
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
	step(1, func() (e error) { n.AssetID, e = r.Hash32(); return })
	step(2, func() (e error) { n.Amount, e = r.U128(); return })
	step(3, func() (e error) { n.LockRoot, e = r.Hash32(); return })
	step(4, func() (e error) { n.DatumRoot, e = r.Hash32(); return })
	step(5, func() (e error) { n.BirthHeight, e = r.U64(); return })
	step(6, func() (e error) { n.RelativeTimelock, e = r.U32(); return })
	step(7, func() (e error) { n.MemoCommitment, e = r.Hash32(); return })
	return n, err
}

// DecodeNote decodes a standalone canonical NoteV1 (whole input).
func DecodeNote(b []byte) (NoteV1, error) {
	r := codec.NewReader(b)
	n, err := decodeNoteFields(r)
	if err != nil {
		return n, err
	}
	return n, r.Finish()
}

// Encode returns the canonical bytes.
func (n *NoteV1) Encode() []byte {
	w := codec.NewWriter()
	w.Version(1)
	w.Tag(1)
	w.Hash32(n.AssetID)
	w.Tag(2)
	w.U128(n.Amount)
	w.Tag(3)
	w.Hash32(n.LockRoot)
	w.Tag(4)
	w.Hash32(n.DatumRoot)
	w.Tag(5)
	w.U64(n.BirthHeight)
	w.Tag(6)
	w.U32(n.RelativeTimelock)
	w.Tag(7)
	w.Hash32(n.MemoCommitment)
	return w.Bytes()
}

// FeeAuthorizationV1 is the sponsored-fee authorization
// (lumen-objects.md §11).
type FeeAuthorizationV1 struct {
	Amount          codec.U128
	ResourceCeiling ResourceVector6
	ExpiryHeight    uint64
	TxCommitment    [32]byte
	Sponsor         [32]byte
	SignatureSuite  uint16
	Signature       []byte
}

func decodeFeeAuthorization(r *codec.Reader) (FeeAuthorizationV1, error) {
	var f FeeAuthorizationV1
	var err error
	if err = r.Version(1); err != nil {
		return f, err
	}
	step := func(tag uint16, fn func() error) {
		if err != nil {
			return
		}
		if err = r.Tag(tag); err != nil {
			return
		}
		err = fn()
	}
	step(1, func() (e error) { f.Amount, e = r.U128(); return })
	step(2, func() (e error) { f.ResourceCeiling, e = decodeResourceVector6(r); return })
	step(3, func() (e error) { f.ExpiryHeight, e = r.U64(); return })
	step(4, func() (e error) { f.TxCommitment, e = r.Hash32(); return })
	step(5, func() (e error) { f.Sponsor, e = r.Hash32(); return })
	step(6, func() (e error) { f.SignatureSuite, e = r.U16(); return })
	step(7, func() (e error) { f.Signature, e = r.VarBytes(MaxSignatureBytes); return })
	return f, err
}

func (f *FeeAuthorizationV1) encode(w *codec.Writer) {
	w.Version(1)
	w.Tag(1)
	w.U128(f.Amount)
	w.Tag(2)
	f.ResourceCeiling.encode(w)
	w.Tag(3)
	w.U64(f.ExpiryHeight)
	w.Tag(4)
	w.Hash32(f.TxCommitment)
	w.Tag(5)
	w.Hash32(f.Sponsor)
	w.Tag(6)
	w.U16(f.SignatureSuite)
	w.Tag(7)
	w.VarBytes(f.Signature)
}

// ObjectAccessEntry is one object_access_list entry: object id plus a
// read/read-write mode flag (0 = read, 1 = read-write; anything else
// rejects at decode).
type ObjectAccessEntry struct {
	ObjectID [32]byte
	Mode     byte
}

// TransactionV1 is the transaction envelope (lumen-objects.md §5). txid
// commits these bytes; segregated witnesses are separate.
type TransactionV1 struct {
	ChainID          [32]byte
	FormatVersion    uint16
	ExpiryHeight     uint64
	FeePayer         [32]byte
	FeeAuthorization *FeeAuthorizationV1
	ResourceLimits   ResourceVector6
	NoteInputs       [][32]byte
	AccountInputs    [][32]byte
	ObjectAccessList []ObjectAccessEntry
	Actions          [][]byte
	Outputs          []NoteV1
	EvidenceRefs     [][32]byte
	WitnessRoot      [32]byte
}

// DecodeTransaction decodes a canonical TransactionV1 (whole input).
func DecodeTransaction(b []byte) (*TransactionV1, error) {
	r := codec.NewReader(b)
	tx, err := DecodeTransactionFrom(r)
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return tx, nil
}

// DecodeTransactionFrom decodes one canonical TransactionV1 element from
// the reader (element form for list contexts).
func DecodeTransactionFrom(r *codec.Reader) (*TransactionV1, error) {
	return decodeTransactionFields(r)
}

// DecodeObjectAccessEntryFrom decodes one object_access_list entry:
// object id plus the mode flag; a mode outside {0 read, 1 read-write}
// rejects at decode.
func DecodeObjectAccessEntryFrom(r *codec.Reader) (ObjectAccessEntry, error) {
	var e ObjectAccessEntry
	var err error
	if e.ObjectID, err = r.Hash32(); err != nil {
		return e, err
	}
	if e.Mode, err = r.U8(); err != nil {
		return e, err
	}
	if e.Mode > 1 {
		return e, &codec.Error{Class: codec.ErrInvalidValue, Context: "object access mode"}
	}
	return e, nil
}

func decodeTransactionFields(r *codec.Reader) (*TransactionV1, error) {
	tx := &TransactionV1{}
	if err := r.Version(1); err != nil {
		return nil, err
	}
	if err := r.Tag(1); err != nil {
		return nil, err
	}
	var err error
	if tx.ChainID, err = r.Hash32(); err != nil {
		return nil, err
	}
	if err = r.Tag(2); err != nil {
		return nil, err
	}
	if tx.FormatVersion, err = r.U16(); err != nil {
		return nil, err
	}
	if err = r.Tag(3); err != nil {
		return nil, err
	}
	if tx.ExpiryHeight, err = r.U64(); err != nil {
		return nil, err
	}
	if err = r.Tag(4); err != nil {
		return nil, err
	}
	if tx.FeePayer, err = r.Hash32(); err != nil {
		return nil, err
	}
	if err = r.Tag(5); err != nil {
		return nil, err
	}
	present, err := r.OptionalPresence()
	if err != nil {
		return nil, err
	}
	if present {
		fa, err := decodeFeeAuthorization(r)
		if err != nil {
			return nil, err
		}
		tx.FeeAuthorization = &fa
	}
	if err = r.Tag(6); err != nil {
		return nil, err
	}
	if tx.ResourceLimits, err = decodeResourceVector6(r); err != nil {
		return nil, err
	}
	if tx.NoteInputs, err = decodeHash32List(r, 7, MaxNoteInputs); err != nil {
		return nil, err
	}
	if tx.AccountInputs, err = decodeHash32List(r, 8, MaxAccountInputs); err != nil {
		return nil, err
	}
	if err = r.Tag(9); err != nil {
		return nil, err
	}
	nAcc, err := r.ListLen(MaxObjectAccess)
	if err != nil {
		return nil, err
	}
	tx.ObjectAccessList = make([]ObjectAccessEntry, 0, nAcc)
	for range nAcc {
		e, err := DecodeObjectAccessEntryFrom(r)
		if err != nil {
			return nil, err
		}
		tx.ObjectAccessList = append(tx.ObjectAccessList, e)
	}
	if err = r.Tag(10); err != nil {
		return nil, err
	}
	nAct, err := r.ListLen(MaxActions)
	if err != nil {
		return nil, err
	}
	tx.Actions = make([][]byte, 0, nAct)
	for range nAct {
		a, err := r.VarBytes(MaxActionBytes)
		if err != nil {
			return nil, err
		}
		tx.Actions = append(tx.Actions, a)
	}
	if err = r.Tag(11); err != nil {
		return nil, err
	}
	nOut, err := r.ListLen(MaxOutputs)
	if err != nil {
		return nil, err
	}
	tx.Outputs = make([]NoteV1, 0, nOut)
	for range nOut {
		n, err := decodeNoteFields(r)
		if err != nil {
			return nil, err
		}
		tx.Outputs = append(tx.Outputs, n)
	}
	if tx.EvidenceRefs, err = decodeHash32List(r, 12, MaxEvidenceRefs); err != nil {
		return nil, err
	}
	if err = r.Tag(13); err != nil {
		return nil, err
	}
	if tx.WitnessRoot, err = r.Hash32(); err != nil {
		return nil, err
	}
	return tx, nil
}

func decodeHash32List(r *codec.Reader, tag uint16, max uint32) ([][32]byte, error) {
	if err := r.Tag(tag); err != nil {
		return nil, err
	}
	n, err := r.ListLen(max)
	if err != nil {
		return nil, err
	}
	out := make([][32]byte, 0, n)
	for range n {
		h, err := r.Hash32()
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// Encode returns the canonical non-witness body bytes (the txid preimage
// tail).
func (tx *TransactionV1) Encode() []byte {
	w := codec.NewWriter()
	w.Version(1)
	w.Tag(1)
	w.Hash32(tx.ChainID)
	w.Tag(2)
	w.U16(tx.FormatVersion)
	w.Tag(3)
	w.U64(tx.ExpiryHeight)
	w.Tag(4)
	w.Hash32(tx.FeePayer)
	w.Tag(5)
	w.Presence(tx.FeeAuthorization != nil)
	if tx.FeeAuthorization != nil {
		tx.FeeAuthorization.encode(w)
	}
	w.Tag(6)
	tx.ResourceLimits.encode(w)
	encodeHash32List(w, 7, tx.NoteInputs)
	encodeHash32List(w, 8, tx.AccountInputs)
	w.Tag(9)
	w.U32(uint32(len(tx.ObjectAccessList)))
	for _, e := range tx.ObjectAccessList {
		w.Hash32(e.ObjectID)
		w.U8(e.Mode)
	}
	w.Tag(10)
	w.U32(uint32(len(tx.Actions)))
	for _, a := range tx.Actions {
		w.VarBytes(a)
	}
	w.Tag(11)
	w.U32(uint32(len(tx.Outputs)))
	for i := range tx.Outputs {
		w.Fixed(tx.Outputs[i].Encode())
	}
	encodeHash32List(w, 12, tx.EvidenceRefs)
	w.Tag(13)
	w.Hash32(tx.WitnessRoot)
	return w.Bytes()
}

func encodeHash32List(w *codec.Writer, tag uint16, hs [][32]byte) {
	w.Tag(tag)
	w.U32(uint32(len(hs)))
	for _, h := range hs {
		w.Hash32(h)
	}
}

// SignedIntentV1 authorizes one account input (lumen-objects.md §6).
type SignedIntentV1 struct {
	TxCommitment   [32]byte
	SignerScope    byte
	CapabilityRef  *[32]byte
	SignatureSuite uint16
	Signature      []byte
}

func decodeSignedIntent(r *codec.Reader) (SignedIntentV1, error) {
	var s SignedIntentV1
	if err := r.Version(1); err != nil {
		return s, err
	}
	var err error
	if err = r.Tag(1); err != nil {
		return s, err
	}
	if s.TxCommitment, err = r.Hash32(); err != nil {
		return s, err
	}
	if err = r.Tag(2); err != nil {
		return s, err
	}
	if s.SignerScope, err = r.U8(); err != nil {
		return s, err
	}
	if err = r.Tag(3); err != nil {
		return s, err
	}
	present, err := r.OptionalPresence()
	if err != nil {
		return s, err
	}
	if present {
		h, err := r.Hash32()
		if err != nil {
			return s, err
		}
		s.CapabilityRef = &h
	}
	if err = r.Tag(4); err != nil {
		return s, err
	}
	if s.SignatureSuite, err = r.U16(); err != nil {
		return s, err
	}
	if err = r.Tag(5); err != nil {
		return s, err
	}
	if s.Signature, err = r.VarBytes(MaxSignatureBytes); err != nil {
		return s, err
	}
	return s, nil
}

func (s *SignedIntentV1) encode(w *codec.Writer) {
	w.Version(1)
	w.Tag(1)
	w.Hash32(s.TxCommitment)
	w.Tag(2)
	w.U8(s.SignerScope)
	w.Tag(3)
	w.Presence(s.CapabilityRef != nil)
	if s.CapabilityRef != nil {
		w.Hash32(*s.CapabilityRef)
	}
	w.Tag(4)
	w.U16(s.SignatureSuite)
	w.Tag(5)
	w.VarBytes(s.Signature)
}

// TransactionWitnessesV1 is the segregated witness container
// (lumen-v1.md §4.2): intents[i] authorizes account_inputs[i],
// lock_reveals[i] satisfies note_inputs[i].
type TransactionWitnessesV1 struct {
	Intents     []SignedIntentV1
	LockReveals [][]byte
}

// DecodeWitnesses decodes a canonical TransactionWitnessesV1 (whole input).
func DecodeWitnesses(b []byte) (*TransactionWitnessesV1, error) {
	r := codec.NewReader(b)
	tw, err := DecodeWitnessesFrom(r)
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return tw, nil
}

// DecodeWitnessesFrom decodes one canonical TransactionWitnessesV1 element
// from the reader (element form for list contexts).
func DecodeWitnessesFrom(r *codec.Reader) (*TransactionWitnessesV1, error) {
	tw := &TransactionWitnessesV1{}
	if err := r.Version(1); err != nil {
		return nil, err
	}
	if err := r.Tag(1); err != nil {
		return nil, err
	}
	n, err := r.ListLen(MaxIntents)
	if err != nil {
		return nil, err
	}
	tw.Intents = make([]SignedIntentV1, 0, n)
	for range n {
		s, err := decodeSignedIntent(r)
		if err != nil {
			return nil, err
		}
		tw.Intents = append(tw.Intents, s)
	}
	if err := r.Tag(2); err != nil {
		return nil, err
	}
	m, err := r.ListLen(MaxLockReveals)
	if err != nil {
		return nil, err
	}
	tw.LockReveals = make([][]byte, 0, m)
	for range m {
		lr, err := r.VarBytes(MaxLockRevealBytes)
		if err != nil {
			return nil, err
		}
		tw.LockReveals = append(tw.LockReveals, lr)
	}
	return tw, nil
}

// Encode returns the canonical bytes.
func (tw *TransactionWitnessesV1) Encode() []byte {
	w := codec.NewWriter()
	w.Version(1)
	w.Tag(1)
	w.U32(uint32(len(tw.Intents)))
	for i := range tw.Intents {
		tw.Intents[i].encode(w)
	}
	w.Tag(2)
	w.U32(uint32(len(tw.LockReveals)))
	for _, lr := range tw.LockReveals {
		w.VarBytes(lr)
	}
	return w.Bytes()
}
