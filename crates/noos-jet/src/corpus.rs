//! Deterministic differential corpus (E-JET-01 shape): a seeded splitmix64
//! stream drives noun and meter-limit generation, so certification and
//! admission replay byte-identical cases with no host entropy anywhere.

use noos_grain::Noun;

/// splitmix64 (Steele/Lea/Flood): the frozen corpus stream for jet
/// equivalence records. The constants are part of the certificate format.
pub struct SplitMix64(u64);

impl SplitMix64 {
    #[must_use]
    pub fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed)
    }

    // Wrapping arithmetic IS the splitmix64 definition.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-enough residue below `n` (`n == 0` yields 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64().checked_rem(n.max(1)).unwrap_or(0)
    }
}

/// One corpus case: a subject and the meter limits it runs under. Tight
/// limits are generated deliberately so exhaustion is exercised at every
/// charge point of the mirrored schedule.
pub struct Case {
    pub subject: Noun,
    pub step_limit: u64,
    pub arena_limit: u64,
}

/// The `index`-th case of the corpus stream for `seed`. Each case reseeds
/// from `(seed, index)` so cases are independently reproducible.
#[must_use]
pub fn case(seed: u64, index: u32) -> Case {
    let mut rng = SplitMix64::new(seed ^ u64::from(index).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    // Warm the stream so low-entropy seeds still diverge per index.
    let _ = rng.next_u64();
    let subject = noun(&mut rng, 5);
    let (step_limit, arena_limit) = match rng.below(4) {
        // Tight: exhaustion mid-schedule.
        0 => (rng.below(12), rng.below(6)),
        // Medium: exhaustion on larger operands only.
        1 => (rng.below(64), rng.below(32)),
        _ => (100_000, 100_000),
    };
    Case {
        subject,
        step_limit,
        arena_limit,
    }
}

/// Deterministic noun: boundary-heavy atoms and cells under a small depth
/// budget (recursion depth is bounded by `budget`).
#[must_use]
pub fn noun(rng: &mut SplitMix64, budget: u32) -> Noun {
    if budget > 0 && rng.below(100) < 45 {
        let h = noun(rng, budget.saturating_sub(1));
        let t = noun(rng, budget.saturating_sub(1));
        match Noun::cell(h, t) {
            Ok(c) => c,
            // Unreachable at this budget; fall back to a legal atom.
            Err(_) => Noun::atom_u64(0),
        }
    } else {
        atom(rng)
    }
}

/// Boundary-heavy atom distribution: loobeans, u8/u32/u64 edges, wide
/// multi-word atoms (word-count charges), and raw 64-bit values.
fn atom(rng: &mut SplitMix64) -> Noun {
    match rng.below(8) {
        0 => Noun::atom_u64(0),
        1 => Noun::atom_u64(1),
        2 => Noun::atom_u64(rng.below(256)),
        3 => Noun::atom_u64(u64::from(u32::MAX)),
        4 => Noun::atom_u64(u64::from(u32::MAX).saturating_add(1)),
        5 => Noun::atom_u64(rng.next_u64()),
        6 => {
            // 1..=40 raw bytes; atom_from_le_bytes trims to minimal form.
            let len = usize::try_from(rng.below(40).saturating_add(1)).unwrap_or(1);
            let mut bytes = vec![0u8; len];
            for b in bytes.iter_mut() {
                *b = u8::try_from(rng.below(256)).unwrap_or(0);
            }
            Noun::atom_from_le_bytes(&bytes)
        }
        _ => Noun::atom_u64(rng.below(5)),
    }
}
