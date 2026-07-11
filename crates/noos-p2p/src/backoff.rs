//! Reconnect backoff with deterministic jitter (p2p-v1.md §8).
//!
//! Jitter comes from a seeded SplitMix64 stream — never the OS RNG — so the
//! full reconnect schedule is reproducible in tests and simulations. The
//! delay law: attempt `n` (0-based) draws uniformly from
//! `[exp/2, exp]` where `exp = min(base_ms << n, max_ms)`.

/// SplitMix64: tiny, seedable, full-period deterministic generator.
/// Local jitter/scheduling only — NEVER key material (plan §3.2 excludes
/// deterministic randomness from cryptographic paths).
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Exponential backoff with deterministic jitter.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    base_ms: u64,
    max_ms: u64,
    attempt: u32,
    rng: SplitMix64,
}

impl ReconnectBackoff {
    /// PROPOSED-G0 defaults (p2p-v1.md §8): base 200 ms, cap 30 s.
    pub const DEFAULT_BASE_MS: u64 = 200;
    pub const DEFAULT_MAX_MS: u64 = 30_000;

    pub const fn new(base_ms: u64, max_ms: u64, seed: u64) -> Self {
        ReconnectBackoff {
            base_ms,
            max_ms,
            attempt: 0,
            rng: SplitMix64::new(seed),
        }
    }

    /// Next delay in ms; advances the attempt counter.
    pub fn next_delay_ms(&mut self) -> u64 {
        let shift = self.attempt.min(63);
        let exp = self
            .base_ms
            .saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX))
            .min(self.max_ms)
            .max(1);
        self.attempt = self.attempt.saturating_add(1);
        let half = exp / 2;
        half + self.rng.next_u64() % (exp - half + 1)
    }

    /// A successful, handshake-complete connection resets the schedule
    /// (the jitter stream continues; determinism is per-seed, not per-reset).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_per_seed() {
        let mut a = ReconnectBackoff::new(200, 30_000, 42);
        let mut b = ReconnectBackoff::new(200, 30_000, 42);
        let sa: Vec<u64> = (0..32).map(|_| a.next_delay_ms()).collect();
        let sb: Vec<u64> = (0..32).map(|_| b.next_delay_ms()).collect();
        assert_eq!(sa, sb);

        let mut c = ReconnectBackoff::new(200, 30_000, 43);
        let sc: Vec<u64> = (0..32).map(|_| c.next_delay_ms()).collect();
        assert_ne!(sa, sc, "different seed, different jitter");
    }

    #[test]
    fn delays_respect_exponential_envelope_and_cap() {
        let mut b = ReconnectBackoff::new(200, 30_000, 7);
        for n in 0u32..24 {
            let exp = 200u64
                .saturating_mul(1u64.checked_shl(n).unwrap_or(u64::MAX))
                .min(30_000);
            let d = b.next_delay_ms();
            assert!(d >= exp / 2 && d <= exp, "attempt {n}: {d} outside [{}, {exp}]", exp / 2);
        }
    }

    #[test]
    fn reset_restarts_the_envelope() {
        let mut b = ReconnectBackoff::new(200, 30_000, 9);
        for _ in 0..10 {
            b.next_delay_ms();
        }
        b.reset();
        let d = b.next_delay_ms();
        assert!(d >= 100 && d <= 200, "post-reset delay {d} must be first-attempt sized");
    }
}
