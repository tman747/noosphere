// Package grainref is the independent Go implementation of Grain v1, the
// NOOSPHERE 12-opcode deterministic consensus interpreter.
//
// INDEPENDENCE ATTESTATION: this package was authored exclusively from
// protocol/schemas/grain-v1.md and the conformance vectors in
// protocol/vectors/grain/. It shares no code, no FFI, and no translation
// with the Rust reference crates/noos-grain, whose sources were never read.
//
// The observable outcome of an evaluation is the triple
// (value-or-trap, trap_code-if-any, charge); two implementations conform
// iff these triples are identical on all inputs (spec §1).
package grainref

// Frozen v1 limits (spec §2).
const (
	// GrainVersion is the only version this package implements.
	GrainVersion uint32 = 1
	// WordBytes is the cost/arena accounting word size.
	WordBytes = 8
	// MaxAtomBytes bounds the minimal byte length of any atom, decoded or
	// constructed.
	MaxAtomBytes = 65536
	// MaxCellDepth bounds the cell depth of any noun, decoded or constructed.
	MaxCellDepth = 1048576
	// MaxFormulaBytes bounds the encoded byte length accepted by formula decode.
	MaxFormulaBytes = 65536
	// MaxSubjectBytes bounds the encoded byte length accepted by subject decode.
	MaxSubjectBytes = 1048576
	// ArenaMaxWordsPerTx is the protocol cap on the arena limit a transaction
	// may grant.
	ArenaMaxWordsPerTx = 4194304
)

// Frozen v1 cost table in grain-steps (spec §10).
const (
	costCons      uint64 = 4 // dispatch
	costSlotBase  uint64 = 2 // op 0 dispatch; op 9 completion
	costSlotStep  uint64 = 1 // per axis bit after the leader
	costQuote     uint64 = 1 // dispatch
	costApply     uint64 = 4 // dispatch
	costIsCell    uint64 = 2 // dispatch
	costIncBase   uint64 = 2 // completion
	costIncWord   uint64 = 1 // per operand word, completion
	costEqualBase uint64 = 2 // completion
	costEqualNode uint64 = 1 // per node pair visited
	costEqualWord uint64 = 1 // per word of an equal-length atom pair
	costIf        uint64 = 3 // dispatch
	costCompose   uint64 = 3 // dispatch
	costPush      uint64 = 3 // dispatch
	costArm       uint64 = 4 // dispatch
	costEditBase  uint64 = 4 // completion
	costEditStep  uint64 = 4 // per path level (contains 3 alloc steps + 1 walk step)
	// COST_HINT is 0 by the erasability law; no constant is needed.
	costCellAlloc uint64 = 3 // cell allocation: steps == arena words
	cellWords     uint64 = 3
)

// Trap is a stable numeric Grain trap code (spec §5). Zero is reserved and
// never a trap; it means "no trap" in this package's return values.
type Trap uint16

const (
	// TrapNone is not a trap: it is the zero "no trap" sentinel.
	TrapNone Trap = 0
	// TrapInvalidAxis is axis 0 or an axis walk off the tree.
	TrapInvalidAxis Trap = 1
	// TrapTypeMismatch is an atom formula or a wrongly shaped operand.
	TrapTypeMismatch Trap = 2
	// TrapMeterExhausted is a charge exceeding the remaining step budget.
	TrapMeterExhausted Trap = 3
	// TrapMandatoryJetUnavailable is reserved; unreachable in v1.
	TrapMandatoryJetUnavailable Trap = 4
	// TrapNounOversized is an atom or depth limit violation.
	TrapNounOversized Trap = 5
	// TrapUnknownOpcode is a formula head atom outside 0..=11.
	TrapUnknownOpcode Trap = 6
	// TrapUnknownVersion is eval with version != 1.
	TrapUnknownVersion Trap = 7
	// TrapMalformedBytes is any §4.1 encoding grammar violation.
	TrapMalformedBytes Trap = 8
	// TrapAtomBound is an inc result exceeding MaxAtomBytes.
	TrapAtomBound Trap = 9
	// TrapArenaExhausted is an allocation exceeding the arena budget.
	TrapArenaExhausted Trap = 10
	// TrapFormulaOversized is an encoded formula longer than MaxFormulaBytes.
	TrapFormulaOversized Trap = 11
	// TrapSubjectOversized is an encoded subject longer than MaxSubjectBytes.
	TrapSubjectOversized Trap = 12
)
