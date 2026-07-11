package braidref

import "fmt"

// Structural header validation per protocol/vectors/braid/
// braid-header-validation-v1.json and the frozen laws it pins:
// chain identity, ground profile 1, loom lane hard-zero, and
// justified >= finalized checkpoint ordering.

// ValidationErrorClass is a stable header-validation rejection class; the
// string values are exactly the vector error_class literals.
type ValidationErrorClass string

const (
	ErrWrongProtocolIdentity  ValidationErrorClass = "wrong_protocol_identity"
	ErrWrongGroundProfile     ValidationErrorClass = "wrong_ground_profile"
	ErrLoomCreditDisabled     ValidationErrorClass = "loom_credit_disabled"
	ErrJustifiedBelowFinalized ValidationErrorClass = "justified_below_finalized"
)

// ValidationError is a typed structural-validation rejection.
type ValidationError struct {
	Class ValidationErrorClass
}

func (e *ValidationError) Error() string { return string(e.Class) }

func vErr(c ValidationErrorClass) error { return &ValidationError{Class: c} }

// ValidateStructure checks the deterministic per-header laws that need no
// parent context: chain identity (rejects wrong_protocol_identity), Ground
// profile id == 1 under Braid v1, loom credit and loom credit root
// canonical zero while work_loom_credit_enabled = false, and the justified
// checkpoint at or above the finalized checkpoint.
func ValidateStructure(h *BlockHeaderV1, chainID [32]byte) error {
	if h.ChainID != chainID {
		return vErr(ErrWrongProtocolIdentity)
	}
	if h.GroundProfileID != GroundProfileIDV1 {
		return vErr(ErrWrongGroundProfile)
	}
	if !h.LoomCredit.IsZero() || h.LoomCreditRoot != ([32]byte{}) {
		return vErr(ErrLoomCreditDisabled)
	}
	if h.JustifiedCheckpoint.Epoch < h.FinalizedCheckpoint.Epoch {
		return vErr(ErrJustifiedBelowFinalized)
	}
	return nil
}

// ValidateChainLink checks the parent linkage laws for header-first sync:
// parent hash binding, strictly increasing height, and non-decreasing slot.
func ValidateChainLink(parent, child *BlockHeaderV1) error {
	if child.ParentHash != parent.BlockHash() {
		return fmt.Errorf("parent hash mismatch at height %d", child.Height)
	}
	if child.Height != parent.Height+1 {
		return fmt.Errorf("height %d does not extend parent height %d", child.Height, parent.Height)
	}
	if child.Slot < parent.Slot {
		return fmt.Errorf("slot %d behind parent slot %d", child.Slot, parent.Slot)
	}
	return nil
}
