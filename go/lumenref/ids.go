package lumenref

import "encoding/binary"

// Identity derivations per protocol/schemas/lumen-v1.md §4 and the
// registered domains in protocol/spec/crypto-domains-v1.csv.

const (
	noteIDCtx      = "NOOS/NOTE/V1"
	txIDCtx        = "NOOS/TX/ID/V1"
	wtxIDCtx       = "NOOS/TX/WID/V1"
	witnessRootCtx = "NOOS/TX/WROOT/V1"
	objectIDCtx    = "NOOS/OBJECT/ID/V1"
)

// NoteID derives note_id = H("NOOS/NOTE/V1" || creating_txid ||
// output_index_u32_le || canonical_note).
func NoteID(creatingTxID [32]byte, outputIndex uint32, note *NoteV1) [32]byte {
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], outputIndex)
	return DomainHash(noteIDCtx, creatingTxID[:], idx[:], note.Encode())
}

// TxID derives txid = H("NOOS/TX/ID/V1" || canonical non-witness body).
func TxID(tx *TransactionV1) [32]byte {
	return DomainHash(txIDCtx, tx.Encode())
}

// WTxID derives wtxid = H("NOOS/TX/WID/V1" || canonical body || canonical
// witnesses).
func WTxID(tx *TransactionV1, w *TransactionWitnessesV1) [32]byte {
	return DomainHash(wtxIDCtx, tx.Encode(), w.Encode())
}

// WitnessRoot derives witness_root = H("NOOS/TX/WROOT/V1" || canonical
// lock_reveals list) — witness programs only, signatures excluded, keeping
// the txid → signature binding acyclic.
func WitnessRoot(lockReveals [][]byte) [32]byte {
	buf := make([]byte, 0, 4)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(lockReveals)))
	for _, lr := range lockReveals {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(lr)))
		buf = append(buf, lr...)
	}
	return DomainHash(witnessRootCtx, buf)
}

// ObjectID derives object_id = H("NOOS/OBJECT/ID/V1" || creating_txid ||
// action_index_u32_le || class_id_u32_le).
func ObjectID(creatingTxID [32]byte, actionIndex, classID uint32) [32]byte {
	var idx, cls [4]byte
	binary.LittleEndian.PutUint32(idx[:], actionIndex)
	binary.LittleEndian.PutUint32(cls[:], classID)
	return DomainHash(objectIDCtx, creatingTxID[:], idx[:], cls[:])
}
