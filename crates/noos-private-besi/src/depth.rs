//! M-PRIVACY-DEPTH local contract: a published depth/noise budget predicts decryption-failure
//! risk over the refresh-skeleton lattice ops well enough to price evaluation and refresh. The
//! predictor is checked against the actual measured noise of real ciphertext operations
//! (within a factor of two on the whole local corpus), risk bands are monotone in depth, the
//! Fail band coincides exactly with the fail-closed decrypt refusal, and metric gaming (an
//! under-declared budget or a hidden composition step) rejects with a typed error.
//!
//! Non-claim: the relation between this budget and an external attacker's cost is not measured
//! locally; that experiment (E-HFHE-01) stays external.

use crate::refresh::{BASE_NOISE, NOISE_CEILING};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepthError {
    NoiseOverflow,
    /// The declared budget is lower than the recomputed one: metric gaming.
    MetricGamed,
    /// The declared op transcript does not match the executed one: hidden composition leakage.
    HiddenComposition,
}

/// The composition alphabet priced by the depth market, mirroring the refresh-skeleton ops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepthOp {
    /// Add a fresh base-noise ciphertext.
    AddFresh,
    /// Scale by a public plaintext constant.
    MulPlain(u64),
    /// Proof-carrying refresh: resets noise to base.
    Refresh,
}

/// Worst-case noise bound after applying `ops` to a fresh base-noise ciphertext.
pub fn predict_noise(ops: &[DepthOp]) -> Result<u64, DepthError> {
    let mut bound = BASE_NOISE;
    for op in ops {
        bound = match op {
            DepthOp::AddFresh => bound
                .checked_add(BASE_NOISE)
                .ok_or(DepthError::NoiseOverflow)?,
            DepthOp::MulPlain(k) => bound.checked_mul(*k).ok_or(DepthError::NoiseOverflow)?,
            DepthOp::Refresh => BASE_NOISE,
        };
    }
    Ok(bound)
}

/// Monotone risk bands over the predicted bound; `Fail` is exactly the fail-closed region.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RiskBand {
    Low,
    Elevated,
    High,
    Fail,
}

#[must_use]
pub fn band(predicted: u64) -> RiskBand {
    if predicted >= NOISE_CEILING {
        RiskBand::Fail
    } else if predicted >= NOISE_CEILING / 2 {
        RiskBand::High
    } else if predicted >= NOISE_CEILING / 8 {
        RiskBand::Elevated
    } else {
        RiskBand::Low
    }
}

/// Deterministic evaluation price: strictly monotone in the predicted bound, with a band
/// premium. `Fail` is unpriceable (evaluation refuses; refresh must be bought instead).
pub fn price_evaluation(predicted: u64) -> Option<u64> {
    let premium: u64 = match band(predicted) {
        RiskBand::Low => 0,
        RiskBand::Elevated => 1 << 10,
        RiskBand::High => 1 << 14,
        RiskBand::Fail => return None,
    };
    Some(
        (predicted / (1 << 4))
            .saturating_add(premium)
            .saturating_add(1),
    )
}

/// Refresh is priced by the depth it retires: retiring a deeper (noisier) state costs more.
#[must_use]
pub fn price_refresh(predicted: u64) -> u64 {
    (predicted / (1 << 8)).saturating_add(1 << 6)
}

#[must_use]
pub fn transcript_digest(ops: &[DepthOp]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/BESI/PRIVACY-DEPTH/V1");
    for op in ops {
        match op {
            DepthOp::AddFresh => hasher.update(&[1u8]),
            DepthOp::MulPlain(k) => hasher.update(&[2u8]).update(&k.to_le_bytes()),
            DepthOp::Refresh => hasher.update(&[3u8]),
        };
    }
    *hasher.finalize().as_bytes()
}

/// A published budget declaration: the declared bound and the declared composition transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepthDeclaration {
    pub declared_bound: u64,
    pub declared_transcript: [u8; 32],
}

/// Fail-closed declaration check: the executed ops are recomputed; a lower declared bound is
/// metric gaming, a transcript mismatch is hidden composition.
pub fn verify_declaration(
    declaration: &DepthDeclaration,
    executed_ops: &[DepthOp],
) -> Result<(), DepthError> {
    if declaration.declared_transcript != transcript_digest(executed_ops) {
        return Err(DepthError::HiddenComposition);
    }
    let recomputed = predict_noise(executed_ops)?;
    if declaration.declared_bound < recomputed {
        return Err(DepthError::MetricGamed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::refresh::{
        add, decrypt, derive_key, dispatch_refresh, encrypt, measured_noise, mul_plain, AuditKey,
        Ciphertext, RefreshContext, RefreshError, REFRESH_SUITE,
    };

    const MASTER: [u8; 32] = [61u8; 32];

    fn audit() -> AuditKey {
        AuditKey::new([62u8; 32])
    }

    fn refresh_context(step: usize) -> RefreshContext {
        let byte = u8::try_from(step.saturating_add(1)).unwrap_or(u8::MAX);
        RefreshContext {
            chain_id: [1; 32],
            job_id: [byte; 32],
            suite_from: REFRESH_SUITE,
            suite_to: REFRESH_SUITE,
            rights_root_from: [2; 32],
            rights_root_to: [3; 32],
            policy_root_from: [4; 32],
            policy_root_to: [5; 32],
            transcript_root: [6; 32],
            challenge: [byte; 32],
            challenge_issued_at: 1,
            expires_at: 2,
        }
    }

    /// Executes the op sequence on a real ciphertext, returning the final state and epoch.
    fn execute(ops: &[DepthOp], m: u32) -> Ciphertext {
        let sk = derive_key(&MASTER, 0);
        let mut ct = encrypt(&sk, &MASTER, m, BASE_NOISE, 0).unwrap();
        for (step, op) in ops.iter().enumerate() {
            ct = match op {
                DepthOp::AddFresh => {
                    let sk_now = derive_key(&MASTER, ct.key_epoch);
                    let fresh =
                        encrypt(&sk_now, &MASTER, 0, BASE_NOISE, 100 + step as u64).unwrap();
                    add(&ct, &fresh).unwrap()
                }
                DepthOp::MulPlain(k) => mul_plain(&ct, *k).unwrap(),
                DepthOp::Refresh => {
                    dispatch_refresh(
                        &MASTER,
                        &audit(),
                        &ct,
                        &refresh_context(step),
                        200 + step as u64,
                    )
                    .unwrap()
                    .0
                }
            };
        }
        ct
    }

    #[test]
    fn predictor_tracks_actual_noise_within_factor_two_across_compositions() {
        let corpus: Vec<Vec<DepthOp>> = vec![
            vec![],
            vec![DepthOp::AddFresh],
            vec![DepthOp::AddFresh, DepthOp::MulPlain(3)],
            vec![DepthOp::MulPlain(7), DepthOp::AddFresh, DepthOp::AddFresh],
            vec![DepthOp::MulPlain(5), DepthOp::Refresh, DepthOp::AddFresh],
            vec![
                DepthOp::AddFresh,
                DepthOp::MulPlain(2),
                DepthOp::MulPlain(2),
                DepthOp::AddFresh,
            ],
        ];
        for ops in &corpus {
            let predicted = predict_noise(ops).unwrap();
            let ct = execute(ops, 5);
            let sk = derive_key(&MASTER, ct.key_epoch);
            let actual = measured_noise(&sk, &ct);
            assert!(
                predicted >= actual,
                "prediction must upper-bound reality for {ops:?}: {predicted} < {actual}"
            );
            assert!(
                predicted <= actual.saturating_mul(2),
                "prediction must stay within 2x of reality for {ops:?}: {predicted} > 2*{actual}"
            );
            // The tracked ciphertext bound and the market predictor agree exactly.
            assert_eq!(predicted, ct.noise_bound);
        }
    }

    #[test]
    fn risk_bands_are_monotone_in_depth_and_fail_matches_fail_closed_decrypt() {
        // Deepening compositions never lower the band (without refresh).
        let mut ops: Vec<DepthOp> = Vec::new();
        let mut last = band(predict_noise(&ops).unwrap());
        for _ in 0..12 {
            ops.push(DepthOp::MulPlain(4));
            let now = band(predict_noise(&ops).unwrap());
            assert!(now >= last, "band regressed while deepening");
            last = now;
        }
        assert_eq!(last, RiskBand::Fail);
        // Fail band <=> the real decrypt refuses (fail-closed alignment).
        let hot_ops = vec![DepthOp::MulPlain(1 << 12), DepthOp::MulPlain(1 << 12)];
        let predicted = predict_noise(&hot_ops).unwrap();
        assert_eq!(band(predicted), RiskBand::Fail);
        let ct = execute(&hot_ops, 1);
        let sk = derive_key(&MASTER, 0);
        assert_eq!(decrypt(&sk, &ct), Err(RefreshError::BudgetExhausted));
        // Below the ceiling the band is not Fail and decrypt succeeds (MulPlain scales the
        // message homomorphically: 1 * 8 + 0 = 8).
        let cool_ops = vec![DepthOp::MulPlain(8), DepthOp::AddFresh];
        assert_ne!(band(predict_noise(&cool_ops).unwrap()), RiskBand::Fail);
        assert_eq!(decrypt(&sk, &execute(&cool_ops, 1)), Ok(8));
    }

    #[test]
    fn refresh_resets_predicted_and_actual_depth() {
        let ops = vec![DepthOp::MulPlain(1000), DepthOp::Refresh];
        assert_eq!(predict_noise(&ops).unwrap(), BASE_NOISE);
        let ct = execute(&ops, 9);
        assert_eq!(ct.noise_bound, BASE_NOISE);
        let sk = derive_key(&MASTER, ct.key_epoch);
        // Refresh preserves the scaled plaintext (9 * 1000) while resetting noise.
        assert_eq!(decrypt(&sk, &ct), Ok(9000));
    }

    #[test]
    fn pricing_is_monotone_and_fail_is_unpriceable() {
        let mut previous = 0u64;
        for depth in 1..20u64 {
            let predicted = BASE_NOISE * depth * depth;
            if let Some(price) = price_evaluation(predicted) {
                assert!(price >= previous, "evaluation price regressed with depth");
                previous = price;
            }
        }
        assert_eq!(price_evaluation(NOISE_CEILING), None);
        assert!(price_refresh(NOISE_CEILING) > price_refresh(BASE_NOISE));
    }

    #[test]
    fn falsifier_under_declared_budget_is_metric_gaming() {
        let ops = vec![DepthOp::AddFresh, DepthOp::MulPlain(9)];
        let honest = predict_noise(&ops).unwrap();
        let declaration = DepthDeclaration {
            declared_bound: honest - 1,
            declared_transcript: transcript_digest(&ops),
        };
        assert_eq!(
            verify_declaration(&declaration, &ops),
            Err(DepthError::MetricGamed)
        );
        let fair = DepthDeclaration {
            declared_bound: honest,
            declared_transcript: transcript_digest(&ops),
        };
        assert_eq!(verify_declaration(&fair, &ops), Ok(()));
    }

    #[test]
    fn falsifier_hidden_composition_step_rejects() {
        let declared = vec![DepthOp::AddFresh];
        // The executor sneaks in an extra scaling step not present in the declaration.
        let executed = vec![DepthOp::AddFresh, DepthOp::MulPlain(2)];
        let declaration = DepthDeclaration {
            declared_bound: u64::MAX,
            declared_transcript: transcript_digest(&declared),
        };
        assert_eq!(
            verify_declaration(&declaration, &executed),
            Err(DepthError::HiddenComposition)
        );
    }

    #[test]
    fn overflowing_composition_fails_closed() {
        let ops = vec![DepthOp::MulPlain(u64::MAX), DepthOp::MulPlain(u64::MAX)];
        assert_eq!(predict_noise(&ops), Err(DepthError::NoiseOverflow));
    }
}
