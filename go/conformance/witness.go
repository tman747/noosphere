package conformance

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/mindchain/noosphere/go/braidref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Witness vector runners (protocol/vectors/witness/).
//
// Vector-runner fixture conventions (shared context the frozen files
// assume, all values taken from the vectors themselves):
//   - the fixture chain id is 0xc7 * 32 (the chain bound into every
//     signed vote/commit in the corpus);
//   - the vote/certificate/slashing/beacon snapshot is the
//     "membership-fixture-four" case of witness-membership-v1.json,
//     re-selected through SelectMembership (never trusted precomputed);
//   - certificate vote bodies use epoch = target checkpoint epoch;
//   - the beacon fixture reveal is 0x10 * 32 (pinned by the
//     beacon-reveal-hash case);
//   - the invalid-transition re-execution oracle is keyed by the three
//     fixture body refs (0xbb: available+divergent, 0xaa: unavailable,
//     0xcc: available+matching), mirroring what the deterministic
//     re-executor returns for those bodies.

var fixtureChainID = func() [32]byte {
	var c [32]byte
	for i := range c {
		c[i] = 0xc7
	}
	return c
}()

func repeat32(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// membershipInput is the decoded candidate list of one membership case:
// u32 count || canonical WitnessBond*.
func parseMembershipInput(b []byte) ([]braidref.WitnessBond, error) {
	r := codec.NewReader(b)
	n, err := r.ListLen(^uint32(0))
	if err != nil {
		return nil, err
	}
	bonds := make([]braidref.WitnessBond, 0, n)
	for range n {
		bond, err := braidref.DecodeBondFields(r)
		if err != nil {
			return nil, err
		}
		bonds = append(bonds, bond)
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return bonds, nil
}

// fixtureSnapshot loads and re-selects the four-member snapshot.
var fixtureSnapshot = struct {
	sync.Mutex
	cache map[string]*braidref.Snapshot
}{cache: map[string]*braidref.Snapshot{}}

func loadFixtureSnapshot(ctx *runCtx) (*braidref.Snapshot, error) {
	fixtureSnapshot.Lock()
	defer fixtureSnapshot.Unlock()
	if s, ok := fixtureSnapshot.cache[ctx.root]; ok {
		return s, nil
	}
	path := filepath.Join(ctx.root, "witness", "witness-membership-v1.json")
	_, cases, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	for i := range cases {
		c := &cases[i]
		if c.Name != "membership-fixture-four" {
			continue
		}
		var meta struct {
			Epoch      string `json:"epoch"`
			MinBond    string `json:"min_bond"`
			Randomness string `json:"randomness"`
		}
		if err := c.into(&meta); err != nil {
			return nil, err
		}
		bonds, err := parseMembershipInput(mustHex(c.Bytes))
		if err != nil {
			return nil, err
		}
		epoch, _ := strconv.ParseUint(meta.Epoch, 10, 64)
		minBond, _ := new(big.Int).SetString(meta.MinBond, 10)
		snap, err := braidref.SelectMembership(bonds, epoch, minBond, hex32(meta.Randomness))
		if err != nil {
			return nil, err
		}
		fixtureSnapshot.cache[ctx.root] = snap
		return snap, nil
	}
	return nil, fmt.Errorf("membership-fixture-four not found in %s", path)
}

func voteClass(err error) string {
	switch e := err.(type) {
	case *braidref.VoteError:
		return string(e.Class)
	case *codec.Error:
		return string(e.Class)
	}
	return ""
}

func runWitnessVote(ctx *runCtx, cases []vecCase) []CaseResult {
	snap, err := loadFixtureSnapshot(ctx)
	if err != nil {
		return []CaseResult{bad("fixture", "snapshot: %v", err)}
	}
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		vote, err := braidref.DecodeVote(mustHex(c.Bytes))
		if err == nil {
			err = braidref.VerifyVote(vote, snap)
		}
		out = append(out, expectOutcome(c, err, voteClass))
	}
	return out
}

func certClass(err error) string {
	switch e := err.(type) {
	case *braidref.CertError:
		return string(e.Class)
	case *codec.Error:
		return string(e.Class)
	}
	return ""
}

func runWitnessCertificate(ctx *runCtx, cases []vecCase) []CaseResult {
	snap, err := loadFixtureSnapshot(ctx)
	if err != nil {
		return []CaseResult{bad("fixture", "snapshot: %v", err)}
	}
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			Digest string `json:"digest"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		cert, err := braidref.DecodeCertificate(mustHex(c.Bytes))
		if err == nil {
			if meta.Digest != "" {
				if d := cert.Digest(); hex.EncodeToString(d[:]) != meta.Digest {
					out = append(out, bad(c.Name, "content digest mismatch"))
					continue
				}
			}
			err = braidref.VerifyCertificate(cert, snap, fixtureChainID, cert.Target.Epoch)
		}
		out = append(out, expectOutcome(c, err, certClass))
	}
	return out
}

func runWitnessMembership(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			Epoch          string `json:"epoch"`
			MinBond        string `json:"min_bond"`
			Randomness     string `json:"randomness"`
			Outcome        string `json:"outcome"`
			MemberCount    string `json:"member_count"`
			MembershipRoot string `json:"membership_root"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		bonds, err := parseMembershipInput(mustHex(c.Bytes))
		if err != nil {
			out = append(out, bad(c.Name, "candidate decode: %v", err))
			continue
		}
		epoch, _ := strconv.ParseUint(meta.Epoch, 10, 64)
		minBond, _ := new(big.Int).SetString(meta.MinBond, 10)
		snap, err := braidref.SelectMembership(bonds, epoch, minBond, hex32(meta.Randomness))
		if meta.Outcome == "halt" {
			if err == nil {
				out = append(out, bad(c.Name, "expected halt, selection succeeded"))
			} else {
				out = append(out, ok(c.Name))
			}
			continue
		}
		if err != nil {
			out = append(out, bad(c.Name, "selection: %v", err))
			continue
		}
		wantCount, _ := strconv.Atoi(meta.MemberCount)
		if len(snap.Members) != wantCount {
			out = append(out, bad(c.Name, "member count %d, want %d", len(snap.Members), wantCount))
			continue
		}
		root := snap.Root()
		if hex.EncodeToString(root[:]) != meta.MembershipRoot {
			out = append(out, bad(c.Name, "membership root mismatch"))
			continue
		}
		out = append(out, ok(c.Name))
	}
	return out
}

func runWitnessThreshold(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		b := mustHex(c.Bytes)
		if len(b) != 32 {
			out = append(out, bad(c.Name, "payload length %d", len(b)))
			continue
		}
		w := u128LE(b[:16])
		wantQ := u128LE(b[16:])
		if got := braidref.JustificationThreshold(w); got.Cmp(wantQ) != 0 {
			out = append(out, bad(c.Name, "Q %s, want %s", got, wantQ))
			continue
		}
		out = append(out, ok(c.Name))
	}
	return out
}

func u128LE(b []byte) *big.Int {
	lo := binary.LittleEndian.Uint64(b[:8])
	hi := binary.LittleEndian.Uint64(b[8:16])
	v := new(big.Int).SetUint64(hi)
	v.Lsh(v, 64)
	return v.Or(v, new(big.Int).SetUint64(lo))
}

func runWitnessBond(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		_, err := braidref.VerifyBondRegistration(mustHex(c.Bytes))
		out = append(out, expectOutcome(c, err, func(e error) string {
			switch te := e.(type) {
			case *braidref.BondError:
				return string(te.Class)
			case *codec.Error:
				return string(te.Class)
			}
			return ""
		}))
	}
	return out
}

func runWitnessSlashing(ctx *runCtx, cases []vecCase) []CaseResult {
	snap, err := loadFixtureSnapshot(ctx)
	if err != nil {
		return []CaseResult{bad("fixture", "snapshot: %v", err)}
	}
	// Fixture re-execution oracle (see the convention note above).
	reexec := func(bodyRef [32]byte) (bool, [32]byte, [32]byte) {
		switch bodyRef {
		case repeat32(0xbb):
			return true, repeat32(0x02), repeat32(0x03)
		case repeat32(0xcc):
			return true, repeat32(0x01), repeat32(0x03)
		default:
			return false, [32]byte{}, [32]byte{}
		}
	}
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			CurrentEpoch string `json:"current_epoch"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		ev, err := braidref.DecodeSlashingEvidence(mustHex(c.Bytes))
		if err == nil {
			cur, _ := strconv.ParseUint(meta.CurrentEpoch, 10, 64)
			err = braidref.CheckSlashingEvidence(ev, snap, cur,
				braidref.TestnetEvidenceHorizonEpochs, reexec)
		}
		out = append(out, expectOutcome(c, err, nil))
	}
	return out
}

func runWitnessBeacon(ctx *runCtx, cases []vecCase) []CaseResult {
	snap, err := loadFixtureSnapshot(ctx)
	if err != nil {
		return []CaseResult{bad("fixture", "snapshot: %v", err)}
	}
	fixtureReveal := repeat32(0x10)
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			RevealHash   string `json:"reveal_hash"`
			CommitDigest string `json:"commit_digest"`
			Randomness   string `json:"randomness"`
			Bitmap       string `json:"bitmap"`
			WithheldIdx  string `json:"withheld_index"`
			SlotInEpoch  string `json:"slot_in_epoch"`
			IngestTwice  string `json:"ingest_twice"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		switch {
		case meta.RevealHash != "": // beacon-reveal-hash
			got := braidref.RevealHash(hex32(c.Bytes))
			if hex.EncodeToString(got[:]) == meta.RevealHash {
				out = append(out, ok(c.Name))
			} else {
				out = append(out, bad(c.Name, "reveal hash mismatch"))
			}
		case meta.CommitDigest != "": // beacon-commit-digest
			commit, err := braidref.DecodeBeaconCommit(mustHex(c.Bytes))
			if err != nil {
				out = append(out, bad(c.Name, "decode: %v", err))
				continue
			}
			got := braidref.CommitDigest(commit)
			if hex.EncodeToString(got[:]) == meta.CommitDigest {
				out = append(out, ok(c.Name))
			} else {
				out = append(out, bad(c.Name, "commit digest mismatch"))
			}
		case meta.Randomness != "": // beacon-mix-*
			b := mustHex(c.Bytes)
			n := len(snap.Members)
			if len(b) != 32*(n+1) {
				out = append(out, bad(c.Name, "mix payload length %d", len(b)))
				continue
			}
			var prev [32]byte
			copy(prev[:], b[:32])
			contributions := make([][32]byte, n)
			for j := range n {
				copy(contributions[j][:], b[32*(j+1):32*(j+2)])
			}
			if meta.WithheldIdx != "" && meta.WithheldIdx != "none" {
				wi, _ := strconv.Atoi(meta.WithheldIdx)
				contributions[wi] = braidref.RevealHash(contributions[wi])
			}
			got := braidref.BeaconMix(fixtureChainID, snap.Epoch, snap.Root(),
				mustHex(meta.Bitmap), prev, contributions)
			if hex.EncodeToString(got[:]) == meta.Randomness {
				out = append(out, ok(c.Name))
			} else {
				out = append(out, bad(c.Name, "mix randomness mismatch"))
			}
		default: // ingest-law negatives
			commit, err := braidref.DecodeBeaconCommit(mustHex(c.Bytes))
			if err != nil {
				out = append(out, expectOutcome(c, err, nil))
				continue
			}
			st := braidref.NewBeaconState(snap, fixtureChainID)
			slot := uint64(0)
			if meta.SlotInEpoch != "" {
				slot, _ = strconv.ParseUint(meta.SlotInEpoch, 10, 64)
			}
			err = st.IngestCommit(commit, slot)
			if err == nil && meta.IngestTwice == "true" {
				err = st.IngestCommit(commit, slot)
			}
			if err == nil && c.Name == "beacon-reveal-mismatch" {
				err = st.IngestReveal(commit.ValidatorID, fixtureReveal)
			}
			out = append(out, expectOutcome(c, err, nil))
		}
	}
	return out
}
