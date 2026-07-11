// Package receiptref is the independent Go receipt/proof verification
// surface of the MindChain/NOOSPHERE L1: the closed proof-verifier
// registry dispatch and the Weft v0 decode-level object checks.
//
// INDEPENDENCE ATTESTATION (plan §8.5): authored exclusively from the
// frozen documents — protocol/spec/schema-tables/nel-wire.md,
// protocol/schemas/weft-v0.md, protocol/spec/crypto-domains-v1.csv — and
// the frozen vectors in protocol/vectors/weft/. No crates/noos-* source
// was read; no codec was generated; no Rust FFI, consensus library,
// verifier core, or copied oracle is used.
package receiptref

import (
	"fmt"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// VerifierID is a registry-scoped u32 proof-verifier identifier
// (nel-wire.md leaf-receipt envelope, field 1).
type VerifierID uint32

// The closed verifier-ID set (plan §10.8). The set is CLOSED: any other
// id rejects, and SpecializedChunkV1 is registered but disabled.
//
// AMBIGUITY NOTE (reported as a spec defect, never silently resolved):
// nel-wire.md names the closed set but assigns no numeric registry values.
// The values below are sequential declaration-order assignments
// (PROPOSED-G0) and MUST be re-frozen against the registry table before
// any cross-client differential run of leaf receipts.
const (
	VerifierEnvelopeV1         VerifierID = 1
	VerifierRisc0FreivaldsLeaf VerifierID = 2
	VerifierRisc0NonlinearLeaf VerifierID = 3
	VerifierSpecializedChunkV1 VerifierID = 4
)

// LeafKind is envelope field 2: 0 = GEMM Freivalds, 1 = nonlinear
// direct-recompute.
type LeafKind uint8

const (
	LeafGEMMFreivalds      LeafKind = 0
	LeafNonlinearRecompute LeafKind = 1
	leafKindCount                   = 2
)

// LeafReceiptEnvelope is the fixed canonical envelope (nel-wire.md): the
// proof bytes are length-bounded by the verifier registry, never by a
// modeled estimate.
type LeafReceiptEnvelope struct {
	DisputeID         [32]byte
	VerifierID        VerifierID
	LeafKind          LeafKind
	JournalCommitment [32]byte
	ProofBytes        []byte
}

// Verdict is a deterministic verification verdict record. A proof NEVER
// falls back to acceptance: every non-accept path is an explicit reject.
type Verdict struct {
	Accepted bool
	Reason   string
}

func reject(format string, args ...any) Verdict {
	return Verdict{Accepted: false, Reason: fmt.Sprintf(format, args...)}
}

// verifierEntry is one closed-registry row.
type verifierEntry struct {
	name          string
	enabled       bool
	maxProofBytes uint32
	// backend runs the actual proof system. The base-client skeleton
	// registers no backend for the RISC Zero rows yet: dispatch is
	// closed and decode-complete, and a missing backend REJECTS
	// (deterministic "verifier backend unavailable"), never accepts.
	backend func(env *LeafReceiptEnvelope) Verdict
}

// registry is the closed table. Unknown IDs are not present and reject.
var registry = map[VerifierID]verifierEntry{
	VerifierEnvelopeV1: {
		name:          "EnvelopeV1",
		enabled:       true,
		maxProofBytes: 0, // envelope-only verification carries no proof bytes
		backend:       verifyEnvelopeV1,
	},
	VerifierRisc0FreivaldsLeaf: {
		name:          "Risc0FreivaldsLeafV1",
		enabled:       true,
		maxProofBytes: 1 << 20,
	},
	VerifierRisc0NonlinearLeaf: {
		name:          "Risc0NonlinearLeafV1",
		enabled:       true,
		maxProofBytes: 1 << 20,
	},
	VerifierSpecializedChunkV1: {
		name:          "SpecializedChunkV1",
		enabled:       false, // disabled at genesis (plan §10.8)
		maxProofBytes: 1 << 20,
	},
}

// ProofBytesBound returns the registry proof-byte bound for an id, or
// false for unknown ids.
func ProofBytesBound(id VerifierID) (uint32, bool) {
	e, ok := registry[id]
	if !ok {
		return 0, false
	}
	return e.maxProofBytes, true
}

// DecodeLeafReceipt decodes a canonical leaf-receipt envelope (whole
// input). The proof-byte length bound comes from the registry row of the
// declared verifier id; an unknown id rejects at decode, before any proof
// work (crypto-domains CI law d generalized: unknown object/version fails
// before signature or proof work).
func DecodeLeafReceipt(b []byte) (*LeafReceiptEnvelope, error) {
	r := codec.NewReader(b)
	env := &LeafReceiptEnvelope{}
	var err error
	if env.DisputeID, err = r.Hash32(); err != nil {
		return nil, err
	}
	vid, err := r.U32()
	if err != nil {
		return nil, err
	}
	env.VerifierID = VerifierID(vid)
	entry, known := registry[env.VerifierID]
	if !known {
		return nil, fmt.Errorf("unknown verifier id %d: the registry is closed", vid)
	}
	kind, err := r.U8()
	if err != nil {
		return nil, err
	}
	if kind >= leafKindCount {
		return nil, fmt.Errorf("unknown leaf kind %d", kind)
	}
	env.LeafKind = LeafKind(kind)
	if env.JournalCommitment, err = r.Hash32(); err != nil {
		return nil, err
	}
	if env.ProofBytes, err = r.VarBytes(entry.maxProofBytes); err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return env, nil
}

// Dispatch routes a decoded envelope through the closed registry:
// unknown rejects, disabled rejects, a registered-but-unavailable backend
// rejects. There is no path from any failure to acceptance.
func Dispatch(env *LeafReceiptEnvelope) Verdict {
	entry, ok := registry[env.VerifierID]
	if !ok {
		return reject("unknown verifier id %d: the registry is closed", env.VerifierID)
	}
	if !entry.enabled {
		return reject("verifier %s is disabled", entry.name)
	}
	if uint32(len(env.ProofBytes)) > entry.maxProofBytes {
		return reject("proof bytes %d exceed the registry bound %d", len(env.ProofBytes), entry.maxProofBytes)
	}
	if entry.backend == nil {
		// CHECKER-SEMANTICS SEAM (recorded follow-up): the RISC Zero
		// leaf backends bind the chain/model/profile/job/chunk/token/
		// layer/op/span/dimension/quantization/boundary/beacon/image/
		// accept tuple and verify the receipt. Until that backend
		// lands, dispatch REJECTS deterministically.
		return reject("verifier %s: backend unavailable in the base-client skeleton", entry.name)
	}
	return entry.backend(env)
}

// verifyEnvelopeV1 accepts a well-formed envelope with the mandatory
// zero-length proof payload: EnvelopeV1 is the decode-level profile.
func verifyEnvelopeV1(env *LeafReceiptEnvelope) Verdict {
	if len(env.ProofBytes) != 0 {
		return reject("EnvelopeV1 carries no proof bytes")
	}
	if env.JournalCommitment == ([32]byte{}) {
		return reject("EnvelopeV1: zero journal commitment")
	}
	return Verdict{Accepted: true}
}
