//! ODR-parameterized Witness Ring values (constants-v1.toml `[witness]`).
//!
//! The corpus names each rule but not its number; every field cites its ODR
//! row (`protocol/spec/odr-ledger.md`). Mainnet values stay `OWNER_BLOCKED`
//! and cannot enter code through a default: this struct has NO `Default`
//! impl, and the only shipped values are the explicitly labeled valueless
//! testnet fixture (plan §2.5).

/// Parts-per-million denominator for slash/leak fractions.
pub const PPM: u32 = 1_000_000;

/// Witness Ring parameters (per-network; frozen at genesis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessParamsV1 {
    /// Minimum bond, integer micro-NOOS (mainnet: ODR-ECON-001,
    /// OWNER_BLOCKED; testnet fixture below).
    pub min_bond: u128,
    /// Slash burn fraction, ppm (ODR-WITNESS-002).
    pub slash_burn_ppm: u32,
    /// Slash reporter fraction, ppm (ODR-WITNESS-002). The remainder is
    /// locked until exit; conservation is checked, never assumed.
    pub slash_reporter_ppm: u32,
    /// Penalty for a committed-but-withheld beacon reveal, integer
    /// micro-NOOS (ODR-WITNESS-002 family, witness-v1.md §4.3).
    pub missed_reveal_penalty: u128,
    /// Epochs of threshold failure before the inactivity leak engages
    /// (ODR-WITNESS-003).
    pub inactivity_delay_epochs: u64,
    /// Per-epoch nonvoter weight leak once engaged, ppm (ODR-WITNESS-003).
    pub inactivity_leak_ppm: u32,
    /// Evidence horizon: slashing evidence is verifiable this many epochs
    /// back (ODR-WITNESS-005).
    pub evidence_horizon_epochs: u64,
}

impl WitnessParamsV1 {
    /// Valueless testnet fixture (`is_test_fixture` semantics, plan §2.5;
    /// PROPOSED-G0, to be frozen with the G1 vector review).
    ///
    /// * `min_bond` — `constants-v1.toml [test_network]
    ///   testnet_min_bond_micro_noos_test` = 10^9;
    /// * slash split 50% burn / 10% reporter / 40% locked;
    /// * missed-reveal penalty 10^6 micro-NOOS_TEST;
    /// * leak: engages after 4 failed epochs, 10_000 ppm (1%) per epoch;
    /// * evidence horizon 64 epochs.
    #[must_use]
    pub const fn testnet_fixture() -> Self {
        Self {
            min_bond: 1_000_000_000,
            slash_burn_ppm: 500_000,
            slash_reporter_ppm: 100_000,
            missed_reveal_penalty: 1_000_000,
            inactivity_delay_epochs: 4,
            inactivity_leak_ppm: 10_000,
            evidence_horizon_epochs: 64,
        }
    }

    /// Structural validity: fractions must not exceed the whole.
    #[must_use]
    pub const fn fractions_valid(&self) -> bool {
        // Both ppm values are < 2^20; the sum cannot overflow u32.
        self.slash_burn_ppm.saturating_add(self.slash_reporter_ppm) <= PPM
            && self.inactivity_leak_ppm <= PPM
    }
}
