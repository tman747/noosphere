//! The total, bounded v0 relation checker (weft-v0.md §5).
//!
//! Ordered checks are frozen: the FIRST failing check names the
//! [`WeftError`]. Reference integrity resolves only against a
//! [`WeftStoreV0`] whose entries were themselves admitted through this
//! checker — content addressing makes reference cycles unrepresentable, so
//! admission order is dependency order.

use std::collections::BTreeMap;

use crate::objects::{
    CostCertificateV0, JetCertificateV0, JetStatus, MeaningContractV0, NumericProfileV0,
    ObjectKind, SpanStatementV0, TranscriptLayout, WeftObjectV0,
};
use crate::{
    domain_hash, domains, formula_id, Hash32, WeftError, MAX_COST_COEFF, MAX_TERM_EXPONENT,
    MAX_TERM_TOTAL_DEGREE, MAX_TRIAL_ARENA_WORDS, MAX_TRIAL_CHARGE, PROFILE_FORBID_REQUIRED,
    SPAN_DIM_MAX, SPAN_MAX_REPS, SPAN_SHA256_FLAT_V0_RBITS, SPAN_SOUNDNESS_MIN_BITS,
    WEFT_V0_GRAIN_VERSION, ZERO_HASH,
};
use noos_codec::NoosEncode;
use noos_grain::{decode_formula, decode_subject, encode_noun, eval, GrainTrap, Meter};

// ---------------------------------------------------------------------------
// Content addressing
// ---------------------------------------------------------------------------

/// `profile_id = H(D-WEFT-PROFILE || canonical bytes)`.
#[must_use]
pub fn profile_id(p: &NumericProfileV0) -> Hash32 {
    domain_hash(domains::WEFT_PROFILE, &[&p.encode_canonical()])
}

/// `cost_certificate_id = H(D-WEFT-COST || canonical bytes)`.
#[must_use]
pub fn cost_certificate_id(c: &CostCertificateV0) -> Hash32 {
    domain_hash(domains::WEFT_COST, &[&c.encode_canonical()])
}

/// `meaning_id = H(D-WEFT-MEANING || canonical bytes)`.
#[must_use]
pub fn meaning_id(m: &MeaningContractV0) -> Hash32 {
    domain_hash(domains::WEFT_MEANING, &[&m.encode_canonical()])
}

/// `jet_certificate_id = H(D-WEFT-JETCERT || canonical bytes)`.
#[must_use]
pub fn jet_certificate_id(j: &JetCertificateV0) -> Hash32 {
    domain_hash(domains::WEFT_JETCERT, &[&j.encode_canonical()])
}

/// `span_id = H(D-WEFT-SPAN || canonical bytes)`.
#[must_use]
pub fn span_id(s: &SpanStatementV0) -> Hash32 {
    domain_hash(domains::WEFT_SPAN, &[&s.encode_canonical()])
}

/// Content id of any object under its kind's registered domain.
#[must_use]
pub fn content_id(obj: &WeftObjectV0) -> Hash32 {
    match obj {
        WeftObjectV0::Profile(o) => profile_id(o),
        WeftObjectV0::Cost(o) => cost_certificate_id(o),
        WeftObjectV0::Meaning(o) => meaning_id(o),
        WeftObjectV0::Jet(o) => jet_certificate_id(o),
        WeftObjectV0::Span(o) => span_id(o),
    }
}

// ---------------------------------------------------------------------------
// Cost-polynomial arithmetic (all checked; overflow is a rejection, never UB)
// ---------------------------------------------------------------------------

fn pow_checked(base: u128, exp: u8) -> Option<u128> {
    let mut acc: u128 = 1;
    for _ in 0..exp {
        acc = acc.checked_mul(base)?;
    }
    Some(acc)
}

/// Evaluates the certified bound at one size assignment: the `max` over
/// branches of the sum of `coeff * prod(size_i ^ exp_i)`, computed in u128
/// with checked arithmetic; a result above `u64::MAX` (or any intermediate
/// overflow) is [`WeftError::CertBoundOverflow`].
///
/// `sizes.len()` must equal the certificate's size-variable count (the
/// checker enforces this before calling; a mismatch here is also rejected).
pub fn certified_bound(cert: &CostCertificateV0, sizes: &[u64]) -> Result<u64, WeftError> {
    if sizes.len() != cert.size_vars.0.len() {
        return Err(WeftError::CertTrialArity);
    }
    let mut best: u128 = 0;
    for branch in &cert.branches.0 {
        let mut sum: u128 = 0;
        for term in &branch.terms.0 {
            if term.exponents.0.len() != sizes.len() {
                return Err(WeftError::CertTermArity);
            }
            let mut value: u128 = u128::from(term.coeff);
            for (size, &exp) in sizes.iter().zip(term.exponents.0.iter()) {
                let factor =
                    pow_checked(u128::from(*size), exp).ok_or(WeftError::CertBoundOverflow)?;
                value = value
                    .checked_mul(factor)
                    .ok_or(WeftError::CertBoundOverflow)?;
            }
            sum = sum.checked_add(value).ok_or(WeftError::CertBoundOverflow)?;
        }
        best = best.max(sum);
    }
    u64::try_from(best).map_err(|_| WeftError::CertBoundOverflow)
}

/// Which admission path executed a cost-certificate trial. Unsupported
/// numeric profiles are explicitly demoted to raw Grain; callers cannot
/// mistake fallback execution for v0 certification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V0ExecutionMode {
    Certified,
    RawGrainFallback { profile_error: WeftError },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V0Execution {
    pub mode: V0ExecutionMode,
    pub value: Vec<u8>,
    pub spent: u64,
    pub arena_used: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V0FallbackError {
    Certificate(WeftError),
    TrialIndex,
    FallbackBudget,
    GrainTrap(u16),
}

/// Execute one cost-certificate trial under v0 when `profile` is admitted,
/// or under the authoritative raw-Grain meter when it is unsupported.
///
/// Fallback ignores the certificate's cost polynomial, but never its
/// semantic identity: canonical formula decoding, formula-id binding, and
/// canonical subject decoding are mandatory on both paths. Thus fallback
/// can remove Weft execution preference without silently changing meaning.
pub fn execute_v0_or_grain_fallback(
    profile: &NumericProfileV0,
    cert: &CostCertificateV0,
    trial_index: usize,
    fallback_step_limit: u64,
) -> Result<V0Execution, V0FallbackError> {
    let profile_result = check_profile(profile);
    if profile_result.is_ok() {
        check_cost_certificate(cert).map_err(V0FallbackError::Certificate)?;
    } else if fallback_step_limit == 0 || fallback_step_limit > MAX_TRIAL_CHARGE {
        return Err(V0FallbackError::FallbackBudget);
    }

    if cert.grain_version != WEFT_V0_GRAIN_VERSION {
        return Err(V0FallbackError::Certificate(WeftError::CertGrainVersion));
    }
    let formula = decode_formula(&cert.formula_bytes.0)
        .map_err(|_| V0FallbackError::Certificate(WeftError::CertFormulaInvalid))?;
    if formula_id(&cert.formula_bytes.0) != cert.formula_id {
        return Err(V0FallbackError::Certificate(
            WeftError::CertFormulaHashMismatch,
        ));
    }
    let trial = cert
        .trials
        .0
        .get(trial_index)
        .ok_or(V0FallbackError::TrialIndex)?;
    let subject = decode_subject(&trial.subject.0)
        .map_err(|_| V0FallbackError::Certificate(WeftError::CertTrialSubjectInvalid))?;
    let (mode, step_limit) = match profile_result {
        Ok(()) => (
            V0ExecutionMode::Certified,
            certified_bound(cert, &trial.sizes.0).map_err(V0FallbackError::Certificate)?,
        ),
        Err(profile_error) => (
            V0ExecutionMode::RawGrainFallback { profile_error },
            fallback_step_limit,
        ),
    };
    let mut meter = Meter::new(step_limit, MAX_TRIAL_ARENA_WORDS);
    let value = eval(WEFT_V0_GRAIN_VERSION, subject, formula, &mut meter)
        .map_err(|trap| V0FallbackError::GrainTrap(trap.code()))?;
    Ok(V0Execution {
        mode,
        value: encode_noun(&value),
        spent: meter.spent(),
        arena_used: meter.arena_used(),
    })
}

// ---------------------------------------------------------------------------
// Per-object standalone checks (frozen order; first failure names the error)
// ---------------------------------------------------------------------------

fn is_zero(h: &Hash32) -> bool {
    *h == ZERO_HASH
}

/// NumericProfileV0 well-formedness + v0 admissibility (weft-v0.md §5.1).
pub fn check_profile(p: &NumericProfileV0) -> Result<(), WeftError> {
    // 1. name: nonempty, first byte ASCII alpha, rest [A-Za-z0-9._-].
    let name = &p.name.0;
    let name_ok = match name.split_first() {
        None => false,
        Some((first, rest)) => {
            first.is_ascii_alphabetic()
                && rest
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
    };
    if !name_ok {
        return Err(WeftError::ProfileNameInvalid);
    }
    // 2. v0-admissible widths: exactly W8A8 with a 32-bit accumulator.
    if (p.weight_bits, p.activation_bits, p.accum_bits) != (8, 8, 32) {
        return Err(WeftError::ProfileWidthInadmissible);
    }
    // 3. exact integer accumulation (KT-1) is mandatory.
    if p.accum_exact != 1 {
        return Err(WeftError::ProfileAccumNotExact);
    }
    // 4. requant: nonzero multiplier; shift 1..=31 (the round-half-up
    //    constant is 1 << (shift-1), so shift 0 and shift >= 32 are
    //    meaningless for a 32-bit multiplier).
    if p.requant_mult == 0 || p.requant_shift == 0 || p.requant_shift > 31 {
        return Err(WeftError::ProfileRequantInvalid);
    }
    // 5. saturation: the full two's-complement i8 range [-128, 127].
    if (p.saturate_min_twos, p.saturate_max_twos) != (0x80, 0x7f) {
        return Err(WeftError::ProfileSaturateInvalid);
    }
    // 6. forbid mask: exactly float|wrapping|zero_points|kernel_order.
    if p.forbid_flags != PROFILE_FORBID_REQUIRED {
        return Err(WeftError::ProfileForbidInvalid);
    }
    Ok(())
}

/// CostCertificateV0: the certificate law (weft-v0.md §5.2). A declared
/// polynomial is NEVER trusted; this function re-derives every bound and,
/// when the formula is embedded, executes each trial through Grain.
pub fn check_cost_certificate(c: &CostCertificateV0) -> Result<(), WeftError> {
    // 1. grain version.
    if c.grain_version != WEFT_V0_GRAIN_VERSION {
        return Err(WeftError::CertGrainVersion);
    }
    // 2. formula id present.
    if is_zero(&c.formula_id) {
        return Err(WeftError::CertFormulaIdZero);
    }
    // 3. size variables: valid names ([a-z][a-z0-9_]*), unique, max >= 1.
    for (i, var) in c.size_vars.0.iter().enumerate() {
        let name = &var.name.0;
        let ok = match name.split_first() {
            None => false,
            Some((first, rest)) => {
                first.is_ascii_lowercase()
                    && rest
                        .iter()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
            }
        };
        if !ok || var.max_value == 0 {
            return Err(WeftError::CertSizeVarInvalid);
        }
        if c.size_vars.0[..i].iter().any(|prev| prev.name == var.name) {
            return Err(WeftError::CertSizeVarInvalid);
        }
    }
    // 4. at least one branch; every branch nonempty.
    if c.branches.0.is_empty() || c.branches.0.iter().any(|b| b.terms.0.is_empty()) {
        return Err(WeftError::CertNoBranches);
    }
    // 5. per-term shape: arity, degree caps, coefficient range.
    let arity = c.size_vars.0.len();
    for branch in &c.branches.0 {
        for term in &branch.terms.0 {
            if term.exponents.0.len() != arity {
                return Err(WeftError::CertTermArity);
            }
            let mut total: u32 = 0;
            for &e in &term.exponents.0 {
                if e > MAX_TERM_EXPONENT {
                    return Err(WeftError::CertDegreeExceeded);
                }
                total = total.saturating_add(u32::from(e));
            }
            if total > MAX_TERM_TOTAL_DEGREE {
                return Err(WeftError::CertDegreeExceeded);
            }
            if term.coeff == 0 || term.coeff > MAX_COST_COEFF {
                return Err(WeftError::CertCoeffInvalid);
            }
        }
    }
    // 6. the bound must be representable at the declared maxima. Terms have
    //    nonnegative coefficients, so the polynomial is monotone: passing
    //    here guarantees every in-range trial bound is representable too.
    let max_sizes: Vec<u64> = c.size_vars.0.iter().map(|v| v.max_value).collect();
    certified_bound(c, &max_sizes)?;
    // 7. embedded formula and trial pairing.
    if c.formula_bytes.0.is_empty() {
        if !c.trials.0.is_empty() {
            return Err(WeftError::CertTrialsWithoutFormula);
        }
        return Ok(());
    }
    let formula = decode_formula(&c.formula_bytes.0).map_err(|_| WeftError::CertFormulaInvalid)?;
    if formula_id(&c.formula_bytes.0) != c.formula_id {
        return Err(WeftError::CertFormulaHashMismatch);
    }
    if c.trials.0.is_empty() {
        return Err(WeftError::CertNoTrials);
    }
    // 8. trials, in order: arity, range, subject decode, budget, execution.
    for trial in &c.trials.0 {
        if trial.sizes.0.len() != arity {
            return Err(WeftError::CertTrialArity);
        }
        for (size, var) in trial.sizes.0.iter().zip(c.size_vars.0.iter()) {
            if *size > var.max_value {
                return Err(WeftError::CertTrialSizeRange);
            }
        }
        let subject =
            decode_subject(&trial.subject.0).map_err(|_| WeftError::CertTrialSubjectInvalid)?;
        let bound = certified_bound(c, &trial.sizes.0)?;
        if bound > MAX_TRIAL_CHARGE {
            return Err(WeftError::CertTrialBudgetExceeded);
        }
        // The meter IS the bound assertion: a run needing more than `bound`
        // steps exhausts the meter, which is exactly "actual charge exceeds
        // the certified bound".
        let mut meter = Meter::new(bound, MAX_TRIAL_ARENA_WORDS);
        match eval(WEFT_V0_GRAIN_VERSION, subject, formula.clone(), &mut meter) {
            Ok(_) => {}
            Err(GrainTrap::MeterExhausted) => return Err(WeftError::CertChargeExceedsBound),
            Err(_) => return Err(WeftError::CertTrialTrapped),
        }
    }
    Ok(())
}

/// JetCertificateV0 (weft-v0.md §5.3): standalone laws plus store-resolved
/// reference integrity.
pub fn check_jet_certificate(j: &JetCertificateV0, store: &WeftStoreV0) -> Result<(), WeftError> {
    if j.grain_version != WEFT_V0_GRAIN_VERSION {
        return Err(WeftError::JetGrainVersion);
    }
    if is_zero(&j.formula_id) {
        return Err(WeftError::JetFormulaIdZero);
    }
    if is_zero(&j.impl_hash) {
        return Err(WeftError::JetImplHashZero);
    }
    let triple = &j.target_triple.0;
    if triple.is_empty() || triple.iter().any(|b| !(0x21..=0x7e).contains(b)) {
        return Err(WeftError::JetTargetInvalid);
    }
    if is_zero(&j.corpus_root) {
        return Err(WeftError::JetCorpusZero);
    }
    if j.bond_micro_noos == 0 {
        return Err(WeftError::JetBondZero);
    }
    // Status/height law (ch06 §5.4 lifecycle): pre-admission states carry no
    // heights; admitted states carry exactly the admission height; quarantine
    // and revocation carry a revocation height not before any admission.
    let heights_ok = match j.status {
        JetStatus::Proposed | JetStatus::Challengeable => {
            j.admitted_height == 0 && j.revoked_height == 0
        }
        JetStatus::Admitted | JetStatus::Superseded => {
            j.admitted_height > 0 && j.revoked_height == 0
        }
        JetStatus::Quarantined | JetStatus::Revoked => {
            j.revoked_height > 0 && j.revoked_height >= j.admitted_height
        }
    };
    if !heights_ok {
        return Err(WeftError::JetHeightsInconsistent);
    }
    if !is_zero(&j.profile_id) && !store.profiles.contains_key(&j.profile_id) {
        return Err(WeftError::JetProfileUnresolved);
    }
    if !is_zero(&j.cost_certificate_id) {
        let Some(cert) = store.costs.get(&j.cost_certificate_id) else {
            return Err(WeftError::JetCostUnresolved);
        };
        if cert.formula_id != j.formula_id {
            return Err(WeftError::JetCostFormulaMismatch);
        }
    }
    Ok(())
}

/// MeaningContractV0 (weft-v0.md §5.4): standalone laws plus store-resolved
/// reference integrity.
pub fn check_meaning_contract(m: &MeaningContractV0, store: &WeftStoreV0) -> Result<(), WeftError> {
    if m.grain_version != WEFT_V0_GRAIN_VERSION {
        return Err(WeftError::McGrainVersion);
    }
    if is_zero(&m.formula_id) {
        return Err(WeftError::McFormulaIdZero);
    }
    if std::str::from_utf8(&m.type_signature.0).is_err() {
        return Err(WeftError::McTypeSignatureInvalid);
    }
    for (i, pid) in m.profile_ids.0.iter().enumerate() {
        if m.profile_ids.0[..i].contains(pid) {
            return Err(WeftError::McProfileDuplicate);
        }
        if !store.profiles.contains_key(pid) {
            return Err(WeftError::McProfileUnresolved);
        }
    }
    if !is_zero(&m.cost_certificate_id) {
        let Some(cert) = store.costs.get(&m.cost_certificate_id) else {
            return Err(WeftError::McCostUnresolved);
        };
        if cert.formula_id != m.formula_id {
            return Err(WeftError::McCostFormulaMismatch);
        }
    }
    for (i, oid) in m.obligation_ids.0.iter().enumerate() {
        if m.obligation_ids.0[..i].contains(oid) {
            return Err(WeftError::McObligationDuplicate);
        }
        let Some(jet) = store.jets.get(oid) else {
            return Err(WeftError::McObligationUnresolved);
        };
        if jet.formula_id != m.formula_id || jet.grain_version != m.grain_version {
            return Err(WeftError::McObligationMismatch);
        }
    }
    Ok(())
}

/// SpanStatementV0 (weft-v0.md §5.5): transcript-layout conformance and
/// profile resolution.
pub fn check_span_statement(s: &SpanStatementV0, store: &WeftStoreV0) -> Result<(), WeftError> {
    // 1. every dimension must injectively fit the 16-bit transcript packing.
    for dim in [s.shape_m, s.shape_k, s.shape_n] {
        if dim == 0 || dim > SPAN_DIM_MAX {
            return Err(WeftError::SpanShapeBound);
        }
    }
    // 2. the verifier reference must be present.
    if is_zero(&s.verifier_ref) {
        return Err(WeftError::SpanVerifierZero);
    }
    // 3. layout law: SHA256_FLAT_V0 expands 32-bit challenge words.
    match s.transcript_layout {
        TranscriptLayout::Sha256FlatV0 => {
            if s.soundness_rbits != SPAN_SHA256_FLAT_V0_RBITS {
                return Err(WeftError::SpanRbitsLayout);
            }
        }
    }
    // 4. soundness policy: reps 1..=8 and reps * rbits >= 64.
    let bits = u32::from(s.soundness_reps).saturating_mul(u32::from(s.soundness_rbits));
    if s.soundness_reps == 0 || s.soundness_reps > SPAN_MAX_REPS || bits < SPAN_SOUNDNESS_MIN_BITS {
        return Err(WeftError::SpanSoundnessPolicy);
    }
    // 5. beacon discipline: post-commit randomness only.
    if s.beacon_policy != crate::objects::BeaconPolicy::PostCommitRequired {
        return Err(WeftError::SpanBeaconPolicy);
    }
    // 6. the profile must resolve.
    if !store.profiles.contains_key(&s.profile_id) {
        return Err(WeftError::SpanProfileUnresolved);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Store: admitted objects keyed by content id
// ---------------------------------------------------------------------------

/// A set of *admitted* v0 objects keyed by content id. `admit` is the only
/// write path, so every stored object has passed the checker and every
/// reference inside the store resolves to another admitted object.
/// Iteration is deterministic (`BTreeMap`).
#[derive(Debug, Default, Clone)]
pub struct WeftStoreV0 {
    profiles: BTreeMap<Hash32, NumericProfileV0>,
    costs: BTreeMap<Hash32, CostCertificateV0>,
    meanings: BTreeMap<Hash32, MeaningContractV0>,
    jets: BTreeMap<Hash32, JetCertificateV0>,
    spans: BTreeMap<Hash32, SpanStatementV0>,
}

impl WeftStoreV0 {
    #[must_use]
    pub fn new() -> WeftStoreV0 {
        WeftStoreV0::default()
    }

    /// Checks `obj` (against the objects already admitted) and, on success,
    /// stores it under its content id, which is returned. Content
    /// addressing makes re-admission idempotent and cycles unrepresentable:
    /// references must already be in the store, so admission order is
    /// dependency order.
    pub fn admit(&mut self, obj: WeftObjectV0) -> Result<Hash32, WeftError> {
        let id = content_id(&obj);
        match obj {
            WeftObjectV0::Profile(p) => {
                check_profile(&p)?;
                self.profiles.insert(id, p);
            }
            WeftObjectV0::Cost(c) => {
                check_cost_certificate(&c)?;
                self.costs.insert(id, c);
            }
            WeftObjectV0::Jet(j) => {
                check_jet_certificate(&j, self)?;
                self.jets.insert(id, j);
            }
            WeftObjectV0::Meaning(m) => {
                check_meaning_contract(&m, self)?;
                self.meanings.insert(id, m);
            }
            WeftObjectV0::Span(s) => {
                check_span_statement(&s, self)?;
                self.spans.insert(id, s);
            }
        }
        Ok(id)
    }

    /// Canonical whole-input decode of `bytes` as `kind`, then [`Self::admit`].
    /// This is the wire entry point the conformance vectors exercise.
    pub fn admit_bytes(&mut self, kind: ObjectKind, bytes: &[u8]) -> Result<Hash32, WeftError> {
        let obj = WeftObjectV0::decode_canonical(kind, bytes)?;
        self.admit(obj)
    }

    #[must_use]
    pub fn profile(&self, id: &Hash32) -> Option<&NumericProfileV0> {
        self.profiles.get(id)
    }

    #[must_use]
    pub fn cost_certificate(&self, id: &Hash32) -> Option<&CostCertificateV0> {
        self.costs.get(id)
    }

    #[must_use]
    pub fn meaning_contract(&self, id: &Hash32) -> Option<&MeaningContractV0> {
        self.meanings.get(id)
    }

    #[must_use]
    pub fn jet_certificate(&self, id: &Hash32) -> Option<&JetCertificateV0> {
        self.jets.get(id)
    }

    #[must_use]
    pub fn span_statement(&self, id: &Hash32) -> Option<&SpanStatementV0> {
        self.spans.get(id)
    }

    /// Total number of admitted objects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles
            .len()
            .saturating_add(self.costs.len())
            .saturating_add(self.meanings.len())
            .saturating_add(self.jets.len())
            .saturating_add(self.spans.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
