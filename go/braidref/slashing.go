package braidref

import (
	"fmt"

	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Slashing evidence per protocol/schemas/witness-v1.md §1.4: a closed
// declaration-order u16 enum of three offense classes. Unavailability
// alone is NEVER slashable (ch01 §4.8 rule 3); evidence is valid only
// through the evidence horizon.

// Offense discriminants (declaration order).
const (
	OffenseDoubleVote            uint16 = 0
	OffenseSurroundVote          uint16 = 1
	OffenseInvalidTransitionVote uint16 = 2
	offenseCount                 uint16 = 3
)

// TestnetEvidenceHorizonEpochs is the testnet fixture horizon
// (ODR-WITNESS-005 leaves the production value unresolved; the frozen
// vectors pin 64 for the NOOS_TEST fixture).
const TestnetEvidenceHorizonEpochs = 64

// DivergenceProofV1 carries the claimed vs recomputed roots of an
// invalid-transition offense.
type DivergenceProofV1 struct {
	ClaimedStateRoot      [32]byte
	RecomputedStateRoot   [32]byte
	ClaimedReceiptRoot    [32]byte
	RecomputedReceiptRoot [32]byte
}

// SlashingEvidence is the decoded evidence union.
type SlashingEvidence struct {
	Offense uint16
	// DoubleVote / SurroundVote carry two votes; the surround labels are
	// VoteA = outer, VoteB = inner.
	VoteA, VoteB *FinalityVote
	// InvalidTransitionVote carries one vote plus body reference and
	// divergence proof.
	Vote            *FinalityVote
	BodyRef         [32]byte
	DivergenceProof *DivergenceProofV1
}

// DecodeSlashingEvidence decodes canonical evidence (whole input).
func DecodeSlashingEvidence(b []byte) (*SlashingEvidence, error) {
	r := codec.NewReader(b)
	d, err := r.Discriminant(offenseCount)
	if err != nil {
		return nil, err
	}
	ev := &SlashingEvidence{Offense: d}
	switch d {
	case OffenseDoubleVote, OffenseSurroundVote:
		a, err := decodeVoteFields(r)
		if err != nil {
			return nil, err
		}
		b2, err := decodeVoteFields(r)
		if err != nil {
			return nil, err
		}
		ev.VoteA, ev.VoteB = &a, &b2
	case OffenseInvalidTransitionVote:
		v, err := decodeVoteFields(r)
		if err != nil {
			return nil, err
		}
		ev.Vote = &v
		if ev.BodyRef, err = r.Hash32(); err != nil {
			return nil, err
		}
		var p DivergenceProofV1
		if err = r.Version(1); err != nil {
			return nil, err
		}
		step := func(tag uint16, dst *[32]byte) error {
			if err := r.Tag(tag); err != nil {
				return err
			}
			h, err := r.Hash32()
			if err != nil {
				return err
			}
			*dst = h
			return nil
		}
		if err = step(1, &p.ClaimedStateRoot); err != nil {
			return nil, err
		}
		if err = step(2, &p.RecomputedStateRoot); err != nil {
			return nil, err
		}
		if err = step(3, &p.ClaimedReceiptRoot); err != nil {
			return nil, err
		}
		if err = step(4, &p.RecomputedReceiptRoot); err != nil {
			return nil, err
		}
		ev.DivergenceProof = &p
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return ev, nil
}

// ReExecutor is the deterministic re-execution seam for invalid-transition
// evidence: given a body reference it reports whether the complete
// committed body is available and, if so, the re-executed state and
// receipt roots.
type ReExecutor func(bodyRef [32]byte) (available bool, stateRoot, receiptRoot [32]byte)

// CheckSlashingEvidence validates decoded evidence at currentEpoch against
// the epoch snapshot:
//
//   - DoubleVote: same validator, same target epoch, DISTINCT targets.
//   - SurroundVote: the outer interval strictly surrounds the inner on
//     both ends (outer.source < inner.source AND inner.target <
//     outer.target).
//   - InvalidTransitionVote: the complete committed body must be
//     available AND deterministic re-execution must diverge from the
//     claimed roots; the proof's recomputed roots must equal the
//     re-execution. Unavailability alone is never slashable.
//
// Every embedded vote must verify against the snapshot; the offense epoch
// must lie within the evidence horizon of currentEpoch.
func CheckSlashingEvidence(ev *SlashingEvidence, snap *Snapshot, currentEpoch, horizonEpochs uint64, reexec ReExecutor) error {
	horizon := func(offenseEpoch uint64) error {
		if currentEpoch > offenseEpoch && currentEpoch-offenseEpoch > horizonEpochs {
			return fmt.Errorf("offense epoch %d beyond the %d-epoch evidence horizon at epoch %d",
				offenseEpoch, horizonEpochs, currentEpoch)
		}
		return nil
	}
	switch ev.Offense {
	case OffenseDoubleVote:
		a, b := ev.VoteA, ev.VoteB
		if a.ValidatorID != b.ValidatorID {
			return fmt.Errorf("double vote: distinct validators")
		}
		if a.Target.Epoch != b.Target.Epoch {
			return fmt.Errorf("double vote: distinct target epochs")
		}
		if a.Target == b.Target {
			return fmt.Errorf("double vote: votes share one target")
		}
		if err := horizon(a.Target.Epoch); err != nil {
			return err
		}
		if err := VerifyVote(a, snap); err != nil {
			return fmt.Errorf("vote a: %w", err)
		}
		if err := VerifyVote(b, snap); err != nil {
			return fmt.Errorf("vote b: %w", err)
		}
		return nil
	case OffenseSurroundVote:
		outer, inner := ev.VoteA, ev.VoteB
		if outer.ValidatorID != inner.ValidatorID {
			return fmt.Errorf("surround vote: distinct validators")
		}
		if !(outer.Source.Epoch < inner.Source.Epoch && inner.Target.Epoch < outer.Target.Epoch) {
			return fmt.Errorf("surround vote: outer does not strictly surround inner")
		}
		if err := horizon(outer.Target.Epoch); err != nil {
			return err
		}
		if err := VerifyVote(outer, snap); err != nil {
			return fmt.Errorf("outer vote: %w", err)
		}
		if err := VerifyVote(inner, snap); err != nil {
			return fmt.Errorf("inner vote: %w", err)
		}
		return nil
	case OffenseInvalidTransitionVote:
		if err := horizon(ev.Vote.Target.Epoch); err != nil {
			return err
		}
		if err := VerifyVote(ev.Vote, snap); err != nil {
			return fmt.Errorf("vote: %w", err)
		}
		if reexec == nil {
			return fmt.Errorf("invalid transition: no re-executor")
		}
		available, stateRoot, receiptRoot := reexec(ev.BodyRef)
		if !available {
			return fmt.Errorf("invalid transition: body unavailable — unavailability alone is never slashable")
		}
		p := ev.DivergenceProof
		if p.RecomputedStateRoot != stateRoot || p.RecomputedReceiptRoot != receiptRoot {
			return fmt.Errorf("invalid transition: proof recomputation does not match deterministic re-execution")
		}
		if p.ClaimedStateRoot == stateRoot && p.ClaimedReceiptRoot == receiptRoot {
			return fmt.Errorf("invalid transition: re-execution matched the vote — no divergence")
		}
		return nil
	default:
		return fmt.Errorf("unknown offense %d", ev.Offense)
	}
}
