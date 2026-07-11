//! Fork-choice tuple (plan §6.4; ch01 §4.5 / M-CLOCK).
//!
//! ```text
//! ForkScore(t) = (
//!   finalized_checkpoint_epoch(t),   // finality hand: never outweighed
//!   justified_checkpoint_epoch(t),   // a higher justified outranks work
//!   cumulative_work_since_finalized, // saturating Σ G(b)+L(b), L = 0
//!   inverse_lexicographic_block_hash // lower hash wins; zero security weight
//! )
//! ```
//!
//! The head is the lexicographic MAXIMUM of this tuple over valid tips.
//!
//! ## The inverse-hash tiebreak, precisely
//!
//! ch01 §4.5: "The last field selects the numerically smaller block hash
//! deterministically and carries no security weight." Frozen here as: the
//! canonical 32 block-hash bytes are compared **byte-lexicographically**
//! (equivalently: as a big-endian 256-bit integer), and between two tips
//! equal on the first three components the tip with the **smaller** hash
//! ranks HIGHER. Since distinct blocks have distinct hashes, total order —
//! and therefore head selection — is strict and deterministic.
//!
//! ## Finality dominance
//!
//! The finalized epoch is the most significant component, so a branch
//! carrying astronomically more cumulative work but an older finalized
//! checkpoint ALWAYS loses (tested against `U256::MAX`-scale work). A chain
//! conflicting with the local finalized checkpoint never even reaches
//! scoring — the DAG excludes it from the tip set.

use core::cmp::Ordering;
use noos_ground::U256;

/// Saturating `U256` addition: `min(a + b, 2^256 - 1)`. Cumulative proposal
/// work saturates rather than wraps (ch01 §4.5 "saturating unsigned sum").
#[must_use]
pub fn u256_saturating_add(a: &U256, b: &U256) -> U256 {
    let mut limbs = [0_u64; 4];
    let mut carry = false;
    for (out, (x, y)) in limbs.iter_mut().zip(a.limbs().iter().zip(b.limbs().iter())) {
        let (s1, c1) = x.overflowing_add(*y);
        let (s2, c2) = s1.overflowing_add(u64::from(carry));
        *out = s2;
        carry = c1 || c2;
    }
    if carry {
        U256::MAX
    } else {
        U256::from_limbs(limbs)
    }
}

/// The fork-choice tuple of one tip. `Ord` implements the exact
/// lexicographic law; the maximum is the head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkScore {
    /// Epoch of the tip header's claimed finalized checkpoint.
    pub finalized_epoch: u64,
    /// Epoch of the tip header's claimed justified checkpoint.
    pub justified_epoch: u64,
    /// Saturating Σ `G(b)+L(b)` strictly above the local finalized
    /// checkpoint block, up to and including the tip.
    pub work_since_finalized: U256,
    /// Canonical block hash bytes; final inverse tiebreak.
    pub block_hash: [u8; 32],
}

impl Ord for ForkScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.finalized_epoch
            .cmp(&other.finalized_epoch)
            .then_with(|| self.justified_epoch.cmp(&other.justified_epoch))
            .then_with(|| self.work_since_finalized.cmp(&other.work_since_finalized))
            // Inverse: the SMALLER hash ranks higher. [u8; 32] `Ord` is
            // byte-lexicographic == big-endian numeric.
            .then_with(|| other.block_hash.cmp(&self.block_hash))
    }
}

impl PartialOrd for ForkScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
