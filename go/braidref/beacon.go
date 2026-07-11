package braidref

import (
	"encoding/binary"
	"fmt"

	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Epoch randomness: delay-VRF commit/reveal mix per protocol/schemas/
// witness-v1.md §4 and the registered D-BEACON-* domains.

const (
	beaconCommitCtx = "NOOS/BEACON/COMMIT/V1"
	beaconRevealCtx = "NOOS/BEACON/REVEAL/V1"
	beaconMixCtx    = "NOOS/BEACON/MIX/V1"

	// BeaconCommitCutoffSlotOffset: commits for epoch e accept while
	// slot_in_epoch < 192 (constants-v1.toml [witness], frozen with the
	// beacon vectors).
	BeaconCommitCutoffSlotOffset = 192
)

// BeaconCommitV1 is one witness's commitment object.
type BeaconCommitV1 struct {
	ChainID        [32]byte
	Epoch          uint64
	MembershipRoot [32]byte
	ValidatorID    [32]byte
	RevealHash     [32]byte
}

// DecodeBeaconCommit decodes a canonical BeaconCommitV1 (whole input).
func DecodeBeaconCommit(b []byte) (*BeaconCommitV1, error) {
	r := codec.NewReader(b)
	var c BeaconCommitV1
	var err error
	if err = r.Version(1); err != nil {
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
	step(1, func() (e error) { c.ChainID, e = r.Hash32(); return })
	step(2, func() (e error) { c.Epoch, e = r.U64(); return })
	step(3, func() (e error) { c.MembershipRoot, e = r.Hash32(); return })
	step(4, func() (e error) { c.ValidatorID, e = r.Hash32(); return })
	step(5, func() (e error) { c.RevealHash, e = r.Hash32(); return })
	if err != nil {
		return nil, err
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return &c, nil
}

// RevealHash is the D-BEACON-REVEAL law: H(ctx || 32-byte delay-VRF
// reveal) — the value bound inside the commit and substituted as m_i for
// withheld reveals.
func RevealHash(reveal [32]byte) [32]byte {
	return lumenref.DomainHash(beaconRevealCtx, reveal[:])
}

// CommitDigest is the D-BEACON-COMMIT law: c_i = H(ctx || chain_id ||
// epoch_le || membership_root || validator_id || reveal_hash).
func CommitDigest(c *BeaconCommitV1) [32]byte {
	var epochLE [8]byte
	binary.LittleEndian.PutUint64(epochLE[:], c.Epoch)
	return lumenref.DomainHash(beaconCommitCtx,
		c.ChainID[:], epochLE[:], c.MembershipRoot[:], c.ValidatorID[:], c.RevealHash[:])
}

// BeaconMix is the D-BEACON-MIX law: R_e = H(ctx || chain_id || epoch_le
// || membership_root || bitmap || prev_finalized_certificate_digest ||
// m_1 || ... || m_n) with the contributions in canonical membership order
// (m_i = reveal_i if revealed, else the already-committed reveal hash).
func BeaconMix(chainID [32]byte, epoch uint64, membershipRoot [32]byte, bitmap []byte, prevCertDigest [32]byte, contributions [][32]byte) [32]byte {
	var epochLE [8]byte
	binary.LittleEndian.PutUint64(epochLE[:], epoch)
	parts := make([][]byte, 0, 5+len(contributions))
	parts = append(parts, chainID[:], epochLE[:], membershipRoot[:], bitmap, prevCertDigest[:])
	for i := range contributions {
		parts = append(parts, contributions[i][:])
	}
	return lumenref.DomainHash(beaconMixCtx, parts...)
}

// BeaconState tracks one epoch's commit/reveal phase against a snapshot.
// The exactly-one-commit and post-cutoff laws are enforced at ingest.
type BeaconState struct {
	snap    *Snapshot
	chainID [32]byte
	commits map[[32]byte][32]byte // validator_id -> reveal hash
	reveals map[[32]byte][32]byte // validator_id -> reveal
}

// NewBeaconState creates the per-epoch state.
func NewBeaconState(snap *Snapshot, chainID [32]byte) *BeaconState {
	return &BeaconState{
		snap:    snap,
		chainID: chainID,
		commits: make(map[[32]byte][32]byte),
		reveals: make(map[[32]byte][32]byte),
	}
}

// IngestCommit applies the commit-phase laws: known member, matching
// chain/epoch/membership binding, slot before the frozen cutoff, and
// exactly one commit per witness.
func (s *BeaconState) IngestCommit(c *BeaconCommitV1, slotInEpoch uint64) error {
	if c.ChainID != s.chainID || c.Epoch != s.snap.Epoch || c.MembershipRoot != s.snap.Root() {
		return fmt.Errorf("commit binding mismatch")
	}
	if s.snap.MemberByID(c.ValidatorID) == nil {
		return fmt.Errorf("unknown validator")
	}
	if slotInEpoch >= BeaconCommitCutoffSlotOffset {
		return fmt.Errorf("post_cutoff_commit: slot offset %d >= %d", slotInEpoch, BeaconCommitCutoffSlotOffset)
	}
	if _, dup := s.commits[c.ValidatorID]; dup {
		return fmt.Errorf("duplicate_commit: witness already committed")
	}
	s.commits[c.ValidatorID] = c.RevealHash
	return nil
}

// IngestReveal accepts only the matching reveal for a finalized commit.
func (s *BeaconState) IngestReveal(validatorID, reveal [32]byte) error {
	committed, ok := s.commits[validatorID]
	if !ok {
		return fmt.Errorf("reveal without commit")
	}
	if RevealHash(reveal) != committed {
		return fmt.Errorf("reveal_mismatch: reveal does not hash to the committed value")
	}
	s.reveals[validatorID] = reveal
	return nil
}

// Mix folds the epoch randomness: a missing reveal contributes its
// already-committed hash (withholding cannot select among outputs). The
// returned bitmap marks revealed members LSB-first in membership order.
func (s *BeaconState) Mix(prevCertDigest [32]byte) (randomness [32]byte, bitmap []byte) {
	n := len(s.snap.Members)
	bitmap = make([]byte, (n+7)/8)
	contributions := make([][32]byte, n)
	for i := range s.snap.Members {
		id := s.snap.Members[i].ValidatorID
		if r, ok := s.reveals[id]; ok {
			contributions[i] = r
			bitmap[i/8] |= 1 << (i % 8)
		} else {
			contributions[i] = s.commits[id]
		}
	}
	return BeaconMix(s.chainID, s.snap.Epoch, s.snap.Root(), bitmap, prevCertDigest, contributions), bitmap
}
