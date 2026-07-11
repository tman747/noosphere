package conformance

import (
	"encoding/hex"
	"math/big"

	"github.com/mindchain/noosphere/go/braidref"
)

// Ground vector runners (protocol/vectors/ground/).

func runGroundTicket(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			ChainID              string   `json:"chain_id"`
			ParentHash           string   `json:"parent_hash"`
			ParentGroundTargetLE string   `json:"parent_ground_target_le"`
			ProposalCommitment   string   `json:"proposal_commitment"`
			ProposerPubkey       string   `json:"proposer_pubkey"`
			GenesisTimeMS        uint64   `json:"genesis_time_ms"`
			TimestampMS          uint64   `json:"timestamp_ms"`
			ParentSlot           uint64   `json:"parent_slot"`
			ParentTimestampsMS   []uint64 `json:"parent_timestamps_ms"`
			AdjustedNowMS        uint64   `json:"adjusted_now_ms"`
			MaxFutureDriftMS     uint64   `json:"max_future_drift_ms"`
			Duplicate            bool     `json:"duplicate"`
			Slot                 uint64   `json:"slot"`
			GroundTargetLE       string   `json:"ground_target_le"`
			ExpectedTargetLE     string   `json:"expected_target_le"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		ticket, err := braidref.DecodeGroundTicket(mustHex(c.Bytes))
		if err != nil {
			out = append(out, expectOutcome(c, err, nil))
			continue
		}
		ctx := &braidref.TicketContext{
			ChainID:              hex32(meta.ChainID),
			ParentHash:           hex32(meta.ParentHash),
			ParentGroundTargetLE: hex32(meta.ParentGroundTargetLE),
			ProposalCommitment:   hex32(meta.ProposalCommitment),
			ProposerPubkey:       hex48(meta.ProposerPubkey),
			GenesisTimeMS:        meta.GenesisTimeMS,
			TimestampMS:          meta.TimestampMS,
			Slot:                 meta.Slot,
			ParentSlot:           meta.ParentSlot,
			ParentTimestampsMS:   meta.ParentTimestampsMS,
			AdjustedNowMS:        meta.AdjustedNowMS,
			MaxFutureDriftMS:     meta.MaxFutureDriftMS,
			GroundTargetLE:       hex32(meta.GroundTargetLE),
			ExpectedTargetLE:     hex32(meta.ExpectedTargetLE),
			TupleSeen: func([48]byte, uint64, [32]byte) bool {
				return meta.Duplicate
			},
		}
		err = braidref.VerifyGroundTicket(&ticket, ctx)
		out = append(out, expectOutcome(c, err, nil))
	}
	return out
}

func runPulse(_ *runCtx, cases []vecCase) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for i := range cases {
		c := &cases[i]
		var meta struct {
			AnchorTargetHex   string `json:"anchor_target_hex"`
			ExpectedTargetHex string `json:"expected_target_hex"`
			T                 int64  `json:"t"`
			TA                int64  `json:"t_a"`
			H                 uint64 `json:"h"`
			HA                uint64 `json:"h_a"`
		}
		if err := c.into(&meta); err != nil {
			out = append(out, bad(c.Name, "case meta: %v", err))
			continue
		}
		anchor, okA := new(big.Int).SetString(meta.AnchorTargetHex, 16)
		expected, okE := new(big.Int).SetString(meta.ExpectedTargetHex, 16)
		if !okA || !okE {
			out = append(out, bad(c.Name, "bad hex targets"))
			continue
		}
		got := braidref.PulseTargetV1(anchor, meta.T, meta.TA, meta.H, meta.HA)
		if got.Cmp(expected) != 0 {
			out = append(out, bad(c.Name, "target %x, want %x", got, expected))
			continue
		}
		// The vector also pins the canonical 32-byte LE form.
		le := braidref.U256ToLE(got)
		if hex.EncodeToString(le[:]) != c.Bytes {
			out = append(out, bad(c.Name, "LE form mismatch"))
			continue
		}
		out = append(out, ok(c.Name))
	}
	return out
}
