package braidref

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/mindchain/noosphere/go/lumenref"
	"github.com/mindchain/noosphere/go/lumenref/codec"
)

// Ground ticket law per ch01 §4.2 as frozen in schema-tables/header-body.md
// and constants-v1.toml [ground]:
//
//	GroundChallenge = H("NOOS/GROUND/CHALLENGE/V1" || chain_id ||
//	    parent_hash || parent_ground_target_le || slot_le_u64 ||
//	    proposal_commitment || proposer_pubkey)
//	digest = BLAKE3-256-keyed(key = challenge,
//	    "NOOS/GROUND/TICKET/V1" || nonce_le_u64 || extra_nonce_32)
//	valid iff uint256_le(digest) < ground_target (strict).

const (
	groundChallengeCtx = "NOOS/GROUND/CHALLENGE/V1"
	groundTicketCtx    = "NOOS/GROUND/TICKET/V1"

	// Frozen [ground] constants.
	SlotMS                 = 6000
	EpochLength            = 256
	MaxSlotSkip            = 20
	MedianTimePastBlocks   = 11
	DevnetMaxFutureDriftMS = 12000
)

// GroundTicketV1 is the canonical 76-byte ticket carried in the block body:
// profile_id u32 || nonce u64 || extra_nonce [32] || digest [32].
type GroundTicketV1 struct {
	ProfileID  uint32
	Nonce      uint64
	ExtraNonce [32]byte
	Digest     [32]byte
}

// GroundTicketBytes is the frozen canonical ticket size.
const GroundTicketBytes = 76

func decodeTicketFields(r *codec.Reader) (GroundTicketV1, error) {
	var t GroundTicketV1
	var err error
	if t.ProfileID, err = r.U32(); err != nil {
		return t, err
	}
	if t.Nonce, err = r.U64(); err != nil {
		return t, err
	}
	if t.ExtraNonce, err = r.Hash32(); err != nil {
		return t, err
	}
	t.Digest, err = r.Hash32()
	return t, err
}

// DecodeGroundTicket decodes a canonical GroundTicketV1 (whole input).
func DecodeGroundTicket(b []byte) (GroundTicketV1, error) {
	r := codec.NewReader(b)
	t, err := decodeTicketFields(r)
	if err != nil {
		return t, err
	}
	return t, r.Finish()
}

// Encode returns the canonical 76 bytes.
func (t *GroundTicketV1) Encode() []byte {
	out := make([]byte, 0, GroundTicketBytes)
	out = binary.LittleEndian.AppendUint32(out, t.ProfileID)
	out = binary.LittleEndian.AppendUint64(out, t.Nonce)
	out = append(out, t.ExtraNonce[:]...)
	out = append(out, t.Digest[:]...)
	return out
}

// GroundChallenge recomputes the challenge from already-validated header
// context; the challenge inputs are never carried in the ticket.
func GroundChallenge(chainID, parentHash, parentGroundTargetLE, proposalCommitment [32]byte, slot uint64, proposerPubkey [48]byte) [32]byte {
	var slotLE [8]byte
	binary.LittleEndian.PutUint64(slotLE[:], slot)
	return lumenref.DomainHash(groundChallengeCtx,
		chainID[:], parentHash[:], parentGroundTargetLE[:], slotLE[:],
		proposalCommitment[:], proposerPubkey[:])
}

// TicketDigest recomputes the keyed ticket digest for a challenge.
func TicketDigest(challenge [32]byte, nonce uint64, extraNonce [32]byte) [32]byte {
	var nonceLE [8]byte
	binary.LittleEndian.PutUint64(nonceLE[:], nonce)
	return lumenref.KeyedDomainHash(challenge, groundTicketCtx, nonceLE[:], extraNonce[:])
}

// TicketContext is the validated header/chain context a ticket is checked
// against.
type TicketContext struct {
	ChainID              [32]byte
	ParentHash           [32]byte
	ParentGroundTargetLE [32]byte
	ProposalCommitment   [32]byte
	ProposerPubkey       [48]byte

	GenesisTimeMS      uint64
	TimestampMS        uint64
	Slot               uint64
	ParentSlot         uint64
	ParentTimestampsMS []uint64 // up to the last 11 ancestor timestamps
	AdjustedNowMS      uint64
	MaxFutureDriftMS   uint64

	// GroundTargetLE is the header's claimed target; ExpectedTargetLE is
	// the deterministic Pulse output for the parent. They must agree.
	GroundTargetLE   [32]byte
	ExpectedTargetLE [32]byte

	// TupleSeen reports whether (proposer_pubkey, nonce, extra_nonce)
	// already appears in an ancestor after the last finalized checkpoint
	// (ch01 §4.2 rule 8).
	TupleSeen func(proposer [48]byte, nonce uint64, extraNonce [32]byte) bool
}

// MedianTimePastMS returns the median of the last MedianTimePastBlocks
// ancestor timestamps.
func MedianTimePastMS(timestamps []uint64) uint64 {
	n := len(timestamps)
	if n == 0 {
		return 0
	}
	if n > MedianTimePastBlocks {
		timestamps = timestamps[n-MedianTimePastBlocks:]
		n = MedianTimePastBlocks
	}
	sorted := make([]uint64, n)
	copy(sorted, timestamps)
	for i := 1; i < n; i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	return sorted[n/2]
}

// VerifyGroundTicket checks a decoded ticket against its context under the
// full ch01 §4.2 rule set. Any violation returns a non-nil error.
func VerifyGroundTicket(t *GroundTicketV1, ctx *TicketContext) error {
	// Rule 1: profile.
	if t.ProfileID != GroundProfileIDV1 {
		return fmt.Errorf("ground profile %d, want %d", t.ProfileID, GroundProfileIDV1)
	}
	// Rule 6: slot laws.
	if ctx.TimestampMS < ctx.GenesisTimeMS {
		return fmt.Errorf("timestamp before genesis")
	}
	if want := (ctx.TimestampMS - ctx.GenesisTimeMS) / SlotMS; ctx.Slot != want {
		return fmt.Errorf("slot %d != floor((timestamp-genesis)/%d) = %d", ctx.Slot, SlotMS, want)
	}
	if ctx.Slot < ctx.ParentSlot {
		return fmt.Errorf("slot %d behind parent slot %d", ctx.Slot, ctx.ParentSlot)
	}
	if ctx.Slot-ctx.ParentSlot > MaxSlotSkip {
		return fmt.Errorf("slot skip %d exceeds %d", ctx.Slot-ctx.ParentSlot, MaxSlotSkip)
	}
	// Timestamp laws: strictly above parent MTP-11, at most adjusted
	// time + drift.
	if mtp := MedianTimePastMS(ctx.ParentTimestampsMS); ctx.TimestampMS <= mtp {
		return fmt.Errorf("timestamp %d not above parent MTP %d", ctx.TimestampMS, mtp)
	}
	if ctx.TimestampMS > ctx.AdjustedNowMS+ctx.MaxFutureDriftMS {
		return fmt.Errorf("timestamp %d beyond adjusted now + drift", ctx.TimestampMS)
	}
	// Header target must equal the deterministic Pulse output.
	if ctx.GroundTargetLE != ctx.ExpectedTargetLE {
		return fmt.Errorf("header ground_target differs from Pulse output")
	}
	// Keyed digest recomputation.
	challenge := GroundChallenge(ctx.ChainID, ctx.ParentHash,
		ctx.ParentGroundTargetLE, ctx.ProposalCommitment, ctx.Slot, ctx.ProposerPubkey)
	if TicketDigest(challenge, t.Nonce, t.ExtraNonce) != t.Digest {
		return fmt.Errorf("ticket digest does not match keyed recomputation")
	}
	// Strict target inequality: uint256_le(digest) < ground_target.
	if U256FromLE(t.Digest).Cmp(U256FromLE(ctx.GroundTargetLE)) >= 0 {
		return fmt.Errorf("digest not strictly below ground target")
	}
	// Rule 8: tuple uniqueness since the last finalized checkpoint.
	if ctx.TupleSeen != nil && ctx.TupleSeen(ctx.ProposerPubkey, t.Nonce, t.ExtraNonce) {
		return fmt.Errorf("(proposer, nonce, extra_nonce) tuple reused since last finalized checkpoint")
	}
	return nil
}

// tMaxCopy returns a fresh copy of T_max (for callers needing the clamp
// bound).
func TMax() *big.Int { return new(big.Int).Set(tMax) }
