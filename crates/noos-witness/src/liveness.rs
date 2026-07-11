//! Liveness degradation (witness-v1.md §5; ch01 §4.9).
//!
//! When either threshold fails, Ground blocks continue UNFINALIZED — the
//! [`crate::finality::FinalityTracker`] simply does not advance, and no
//! API in this crate can fabricate a certificate: the only constructor,
//! [`crate::finality::build_certificate`], demands verified quorum inputs.
//!
//! After the inactivity delay (ODR-WITNESS-003) a deterministic leak
//! reduces NONVOTER weight for FUTURE epochs only. The leak is a pure
//! function from a candidate list to a NEW candidate list — it cannot
//! touch an existing (immutable) snapshot, so the current epoch is
//! untouched by construction. Recovery requires a later certificate under
//! a legitimately derived membership root; no administrator signature
//! finalizes anything.

use std::collections::BTreeSet;

use crate::bond::WitnessBondV1;
use crate::params::{WitnessParamsV1, PPM};
use crate::WitnessError;

/// Deterministic inactivity leak for a FUTURE epoch's candidate list.
///
/// * `candidates` — the finalized `e-2` candidate list for the future
///   epoch under construction;
/// * `nonvoters` — validators that failed to vote through the stalled
///   span;
/// * `epochs_without_finality` — length of the stall.
///
/// While `epochs_without_finality ≤ inactivity_delay_epochs` the leak is
/// engaged for zero epochs and the list is returned unchanged. Once
/// engaged, each nonvoter loses `inactivity_leak_ppm` of its remaining
/// bond per epoch beyond the delay (integer ppm, checked, rounding down —
/// the leak never over-collects).
pub fn leak_for_future_epoch(
    candidates: &[WitnessBondV1],
    nonvoters: &BTreeSet<[u8; 32]>,
    epochs_without_finality: u64,
    params: &WitnessParamsV1,
) -> Result<Vec<WitnessBondV1>, WitnessError> {
    let leak_epochs = epochs_without_finality.saturating_sub(params.inactivity_delay_epochs);
    let mut out = Vec::with_capacity(candidates.len());
    for c in candidates {
        let mut bond = c.clone();
        if leak_epochs > 0 && nonvoters.contains(&bond.validator_id) {
            bond.bonded_noos = leaked_weight(bond.bonded_noos, leak_epochs, params)?;
        }
        out.push(bond);
    }
    Ok(out)
}

/// `weight * (1 - leak_ppm/PPM)^epochs`, integer, rounding down each step.
fn leaked_weight(
    weight: u128,
    epochs: u64,
    params: &WitnessParamsV1,
) -> Result<u128, WitnessError> {
    if params.inactivity_leak_ppm > PPM {
        return Err(WitnessError::ArithmeticOverflow);
    }
    let keep_ppm = u128::from(PPM.saturating_sub(params.inactivity_leak_ppm));
    let mut w = weight;
    for _ in 0..epochs {
        if w == 0 {
            break;
        }
        // Division by the nonzero constant PPM cannot panic.
        #[allow(clippy::arithmetic_side_effects)]
        {
            w = w
                .checked_mul(keep_ppm)
                .map(|v| v / u128::from(PPM))
                .ok_or(WitnessError::ArithmeticOverflow)?;
        }
    }
    Ok(w)
}
