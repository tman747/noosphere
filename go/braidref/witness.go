package braidref

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Witness Ring membership per protocol/schemas/witness-v1.md §§1.1, 2 and
// constants-v1.toml [witness].

const (
	NMax  = 256
	NTail = 32
	NHard = 1024

	witnessTiebreakCtx = "NOOS/WITNESS/TIEBREAK/V1"
	witnessSampleCtx   = "NOOS/WITNESS/SAMPLE/V1"

	maxFailureDomainBytes = 1024
)

// WitnessBond is the registration object (witness-v1.md §1.1).
type WitnessBond struct {
	ValidatorID                 [32]byte
	ConsensusBLSKey             [48]byte
	WithdrawalKey               [32]byte
	NetworkEndpointsCommitment  [32]byte
	FailureDomains              []byte
	BondedNoos                  codec.U128
	ActivationEpoch             uint64
	ExitEpoch                   uint64
	ProofpowerAccount           [32]byte
}

// DecodeBondFields decodes one canonical WitnessBond from the reader
// (element form, not whole-input).
func DecodeBondFields(r *codec.Reader) (WitnessBond, error) {
	var b WitnessBond
	var err error
	if err = r.Version(1); err != nil {
		return b, err
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
	step(1, func() (e error) { b.ValidatorID, e = r.Hash32(); return })
	step(2, func() error {
		raw, e := r.Fixed(48)
		if e != nil {
			return e
		}
		copy(b.ConsensusBLSKey[:], raw)
		return nil
	})
	step(3, func() (e error) { b.WithdrawalKey, e = r.Hash32(); return })
	step(4, func() (e error) { b.NetworkEndpointsCommitment, e = r.Hash32(); return })
	step(5, func() (e error) { b.FailureDomains, e = r.VarBytes(maxFailureDomainBytes); return })
	step(6, func() (e error) { b.BondedNoos, e = r.U128(); return })
	step(7, func() (e error) { b.ActivationEpoch, e = r.U64(); return })
	step(8, func() (e error) { b.ExitEpoch, e = r.U64(); return })
	step(9, func() (e error) { b.ProofpowerAccount, e = r.Hash32(); return })
	return b, err
}

// Member is one snapshot entry: raw weight r_i = bonded_noos_i; effective
// weight equals raw at genesis (witness_proofpower_bonus_enabled = false).
type Member struct {
	ValidatorID [32]byte
	BLSKey      [48]byte
	Raw         *big.Int
	Effective   *big.Int
}

// Snapshot is an immutable epoch membership snapshot.
type Snapshot struct {
	Epoch   uint64
	Members []Member // canonical ascending validator_id order
}

// MemberByID returns the member with the given validator id, or nil.
func (s *Snapshot) MemberByID(id [32]byte) *Member {
	for i := range s.Members {
		if s.Members[i].ValidatorID == id {
			return &s.Members[i]
		}
	}
	return nil
}

// TotalRaw sums raw weight.
func (s *Snapshot) TotalRaw() *big.Int {
	w := new(big.Int)
	for i := range s.Members {
		w.Add(w, s.Members[i].Raw)
	}
	return w
}

// TotalEffective sums effective weight.
func (s *Snapshot) TotalEffective() *big.Int {
	w := new(big.Int)
	for i := range s.Members {
		w.Add(w, s.Members[i].Effective)
	}
	return w
}

// Root computes the membership_root: the SMT root over
// validator_id → (consensus_bls_key || raw u128 LE || eff u128 LE)
// (witness-v1.md §2.7, leaf law pinned by witness-membership-v1.json).
func (s *Snapshot) Root() [32]byte {
	var t lumenref.SMT
	for i := range s.Members {
		m := &s.Members[i]
		v := make([]byte, 0, 48+32)
		v = append(v, m.BLSKey[:]...)
		v = appendU128LE(v, m.Raw)
		v = appendU128LE(v, m.Effective)
		t.Put(m.ValidatorID, v)
	}
	return t.Root()
}

func appendU128LE(dst []byte, v *big.Int) []byte {
	be := v.Bytes() // <= 16 bytes for u128 values
	var le [16]byte
	for i, x := range be {
		le[len(be)-1-i] = x
	}
	return append(dst, le[:]...)
}

// JustificationThreshold is the exact integer law Q = floor(2*W/3) + 1
// (witness-v1.md §3; never a rounded two thirds).
func JustificationThreshold(w *big.Int) *big.Int {
	q := new(big.Int).Lsh(w, 1)
	q.Div(q, big.NewInt(3))
	return q.Add(q, big.NewInt(1))
}

// ErrNoValidMembership reports that no cap-satisfying membership vector
// exists for the epoch: the previous epoch set continues for exactly one
// emergency epoch; a second consecutive failure halts finality
// (witness-v1.md §2.5).
type ErrNoValidMembership struct{}

func (ErrNoValidMembership) Error() string { return "no valid membership vector" }

// SelectMembership builds the epoch snapshot from the candidate bonds per
// witness-v1.md §2:
//
//  1. eligibility: activation_epoch <= e < exit_epoch (exit 0 = active),
//     bonded >= minBond;
//  2. active set: top N_max by raw weight, ties by ascending
//     H(D-WITNESS-TIEBREAK || epoch_le || validator_id);
//  3. remainder ordered ascending by H(D-WITNESS-SAMPLE || epoch_le ||
//     R_prev || validator_id); the first N_tail form the reserve and the
//     same order drives cap-repair admission;
//  4. cap law: every key strictly below floor(W/3) of total raw AND
//     effective weight; while violated admit remainder candidates in
//     sample order up to N_hard; if no valid vector exists the caller
//     falls back per the emergency-continuation law.
func SelectMembership(cands []WitnessBond, epoch uint64, minBond *big.Int, randomness [32]byte) (*Snapshot, error) {
	var epochLE [8]byte
	binary.LittleEndian.PutUint64(epochLE[:], epoch)

	type scored struct {
		m      Member
		tb     [32]byte
		sample [32]byte
	}
	eligible := make([]scored, 0, len(cands))
	for i := range cands {
		c := &cands[i]
		if c.ActivationEpoch > epoch {
			continue
		}
		if c.ExitEpoch != 0 && epoch >= c.ExitEpoch {
			continue
		}
		raw := c.BondedNoos.Big()
		if raw.Cmp(minBond) < 0 {
			continue
		}
		eligible = append(eligible, scored{
			m: Member{
				ValidatorID: c.ValidatorID,
				BLSKey:      c.ConsensusBLSKey,
				Raw:         raw,
				Effective:   new(big.Int).Set(raw),
			},
			tb:     lumenref.DomainHash(witnessTiebreakCtx, epochLE[:], c.ValidatorID[:]),
			sample: lumenref.DomainHash(witnessSampleCtx, epochLE[:], randomness[:], c.ValidatorID[:]),
		})
	}
	if len(eligible) == 0 {
		return nil, ErrNoValidMembership{}
	}
	// Rank by descending raw weight, ascending tiebreak hash.
	slices.SortFunc(eligible, func(a, b scored) int {
		if c := b.m.Raw.Cmp(a.m.Raw); c != 0 {
			return c
		}
		return bytes.Compare(a.tb[:], b.tb[:])
	})
	nActive := min(len(eligible), NMax)
	active := eligible[:nActive]
	rest := slices.Clone(eligible[nActive:])
	// Sample order over the remainder.
	slices.SortFunc(rest, func(a, b scored) int {
		return bytes.Compare(a.sample[:], b.sample[:])
	})
	members := make([]Member, 0, nActive)
	for i := range active {
		members = append(members, active[i].m)
	}
	capOK := func(ms []Member) bool {
		w := new(big.Int)
		for i := range ms {
			w.Add(w, ms[i].Raw)
		}
		f := new(big.Int).Div(w, big.NewInt(3))
		for i := range ms {
			// raw == effective at genesis; one check covers both.
			if ms[i].Raw.Cmp(f) >= 0 {
				return false
			}
		}
		return true
	}
	for ri := 0; !capOK(members); ri++ {
		if ri >= len(rest) || len(members) >= NHard {
			return nil, ErrNoValidMembership{}
		}
		members = append(members, rest[ri].m)
	}
	slices.SortFunc(members, func(a, b Member) int {
		return bytes.Compare(a.ValidatorID[:], b.ValidatorID[:])
	})
	return &Snapshot{Epoch: epoch, Members: members}, nil
}
