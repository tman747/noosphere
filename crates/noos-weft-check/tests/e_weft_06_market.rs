//! E-WEFT-06 — local certificate-forgery and economic-substitution
//! falsifiers. Live challenger profitability remains external; locally a
//! certificate can never replace re-derived semantic equivalence.
#![allow(clippy::unwrap_used)]

use noos_grain::{GrainTrap, Meter, Noun};
use noos_jet::jets::{inc_formula, jet_inc, INC_IMPL_TAG};
use noos_jet::{AdmitError, JetRegistry};

const SEED: u64 = 0x4557_4546_5430_3601;
const WINDOW: u32 = 4096;

fn economic_substitute(_subject: &Noun, _meter: &mut Meter) -> Result<Noun, GrainTrap> {
    // A cheap implementation that returns a plausible value while skipping
    // the certified formula and its meter schedule. This is precisely the
    // substitution a market certificate must never authorize.
    Ok(Noun::atom_u64(0))
}

#[test]
fn recomputed_digest_does_not_make_a_forged_certificate_valid() {
    let mut cert =
        JetRegistry::certify(&inc_formula(), INC_IMPL_TAG, jet_inc, SEED, WINDOW).unwrap();
    cert.semantics_hash.0[0] ^= 1;
    cert.digest = cert.compute_digest();

    let mut registry = JetRegistry::new();
    assert_eq!(
        registry.admit(cert, jet_inc),
        Err(AdmitError::SemanticsHashMismatch)
    );
    assert!(registry.is_empty());
}

#[test]
fn certificate_cannot_economically_substitute_for_semantic_equivalence() {
    let cert = JetRegistry::certify(&inc_formula(), INC_IMPL_TAG, jet_inc, SEED, WINDOW).unwrap();
    let mut registry = JetRegistry::new();

    let rejected = registry.admit(cert.clone(), economic_substitute);
    assert!(matches!(
        rejected,
        Err(AdmitError::EquivalenceDivergence { case_index: 0 })
    ));
    assert!(
        registry.is_empty(),
        "a divergent substitute gained preference"
    );

    let admitted = registry.admit(cert, jet_inc).unwrap();
    assert!(registry.cert(&admitted).is_some());
}
