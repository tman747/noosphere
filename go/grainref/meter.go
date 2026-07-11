package grainref

// Meter is the per-evaluation step and arena budget (spec §6).
//
// The reported charge of an evaluation is Spent() at return, success or
// trap. On TrapMeterExhausted the charge is pinned to exactly StepLimit.
// The arena is a cumulative allocation budget: words are never returned
// when nouns die, and structural sharing allocates nothing.
type Meter struct {
	StepLimit  uint64
	Steps      uint64
	ArenaLimit uint64 // words
	Arena      uint64 // words
}

// NewMeter returns a fresh meter with the given step and arena-word limits.
func NewMeter(stepLimit, arenaLimitWords uint64) *Meter {
	return &Meter{StepLimit: stepLimit, ArenaLimit: arenaLimitWords}
}

// Spent returns the steps charged so far — the conformance-triple charge.
func (m *Meter) Spent() uint64 { return m.Steps }

// ArenaUsed returns the cumulative arena words allocated so far.
func (m *Meter) ArenaUsed() uint64 { return m.Arena }

// charge spends c steps; on exhaustion it pins Steps to StepLimit and
// returns TrapMeterExhausted. Steps <= StepLimit is an invariant, so the
// subtraction below cannot underflow and no addition can overflow.
func (m *Meter) charge(c uint64) Trap {
	if c > m.StepLimit-m.Steps {
		m.Steps = m.StepLimit
		return TrapMeterExhausted
	}
	m.Steps += c
	return TrapNone
}

// arenaAdd allocates w arena words; on exhaustion it returns
// TrapArenaExhausted (the steps for the same allocation have already been
// charged and stay spent — spec §6 allocation sequence).
func (m *Meter) arenaAdd(w uint64) Trap {
	if w > m.ArenaLimit-m.Arena {
		return TrapArenaExhausted
	}
	m.Arena += w
	return TrapNone
}
