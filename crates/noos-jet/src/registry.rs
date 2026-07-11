//! The certified jet registry and its opcode-12 dispatch hook.
//!
//! Admission law (A-JET-CERT locally): nothing stated by a certificate is
//! trusted. [`JetRegistry::admit`] re-derives the semantics hash from the
//! certified formula bytes, re-derives the jet id, recomputes the binding
//! digest, and REPLAYS the full differential corpus against the offered
//! native implementation. A forged certificate fails the digest or corpus
//! re-derivation; a certificate whose semantics hash does not match its own
//! formula fails the hash re-derivation. Only entries that survive all of
//! it exist in the registry at all.
//!
//! Dispatch law (M-JET): `[12 id f]` fires a jet only when `id` names an
//! admitted entry AND `semantics_hash(f)` equals the certified semantics
//! hash. Anything else declines, and the interpreter — pure Grain, the
//! authoritative rollback — evaluates `f`.

use core::fmt;
use std::collections::BTreeMap;

use noos_grain::{decode_formula, encode_noun, eval, GrainTrap, JetHook, Meter, Noun};

use crate::cert::{jet_id, semantics_hash, EquivalenceRecord, JetCert, JetId, JET_CERT_VERSION};
use crate::corpus;

const CTX_CORPUS: &[u8] = b"noosphere.jet.corpus.v1";

/// A native jet implementation: must reproduce the exact observational
/// triple of its certified formula, charging `meter` through the same
/// frozen schedule (see [`crate::jets`]).
pub type NativeJet = fn(&Noun, &mut Meter) -> Result<Noun, GrainTrap>;

/// Why certification failed: the native implementation diverged from the
/// interpreter on a corpus case. There is no way to certify past this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertifyError {
    pub diverging_case: u32,
}

impl fmt::Display for CertifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native jet diverged from interpretation on corpus case {}",
            self.diverging_case
        )
    }
}

impl std::error::Error for CertifyError {}

/// Why admission rejected a certificate. Every variant is a hard reject;
/// there is no partial admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// `cert_version` is not the frozen v1.
    UnsupportedCertVersion(u32),
    /// The certified formula bytes do not decode as a Grain formula.
    MalformedFormula,
    /// Re-derived semantics hash differs from the certified one.
    SemanticsHashMismatch,
    /// Re-derived jet id differs from the certified one.
    JetIdMismatch,
    /// The binding digest does not commit to the stated fields (tampered
    /// certificate).
    DigestMismatch,
    /// Corpus replay diverged: the offered native implementation is not
    /// observationally equal to the certified formula.
    EquivalenceDivergence { case_index: u32 },
    /// Corpus replay succeeded but its root differs from the certified
    /// root (forged equivalence record).
    EquivalenceRootMismatch,
    /// The jet id is already admitted.
    DuplicateJetId,
}

impl fmt::Display for AdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmitError::UnsupportedCertVersion(v) => write!(f, "unsupported cert version {v}"),
            AdmitError::MalformedFormula => write!(f, "certified formula bytes are malformed"),
            AdmitError::SemanticsHashMismatch => write!(f, "semantics hash mismatch"),
            AdmitError::JetIdMismatch => write!(f, "jet id mismatch"),
            AdmitError::DigestMismatch => write!(f, "certificate digest mismatch"),
            AdmitError::EquivalenceDivergence { case_index } => {
                write!(f, "equivalence replay diverged at case {case_index}")
            }
            AdmitError::EquivalenceRootMismatch => write!(f, "equivalence root mismatch"),
            AdmitError::DuplicateJetId => write!(f, "jet id already admitted"),
        }
    }
}

impl std::error::Error for AdmitError {}

struct JetEntry {
    cert: JetCert,
    native: NativeJet,
}

/// The certified registry. Keys are the minimal little-endian atom bytes of
/// the jet id (fixed-length digests trim injectively).
#[derive(Default)]
pub struct JetRegistry {
    entries: BTreeMap<Vec<u8>, JetEntry>,
}

impl JetRegistry {
    #[must_use]
    pub fn new() -> JetRegistry {
        JetRegistry::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The admitted certificate for `id`, if any.
    #[must_use]
    pub fn cert(&self, id: &JetId) -> Option<&JetCert> {
        self.entries.get(trim(&id.0)).map(|e| &e.cert)
    }

    /// Certify `native` against `formula` by running the full differential
    /// corpus. A certificate exists ONLY over a corpus that passed.
    pub fn certify(
        formula: &Noun,
        impl_tag: &str,
        native: NativeJet,
        corpus_seed: u64,
        case_count: u32,
    ) -> Result<JetCert, CertifyError> {
        let corpus_root = equivalence_root(formula, native, corpus_seed, case_count)
            .map_err(|diverging_case| CertifyError { diverging_case })?;
        let semantics = semantics_hash(formula);
        let id = jet_id(&semantics, impl_tag);
        let mut cert = JetCert {
            cert_version: JET_CERT_VERSION,
            jet_id: id,
            semantics_hash: semantics,
            impl_tag: impl_tag.to_owned(),
            formula: encode_noun(formula),
            equivalence: EquivalenceRecord {
                corpus_seed,
                case_count,
                corpus_root,
            },
            digest: [0u8; 32],
        };
        cert.digest = cert.compute_digest();
        Ok(cert)
    }

    /// Admit a certificate, re-deriving everything it states. See the
    /// module docs for the rejection law.
    pub fn admit(&mut self, cert: JetCert, native: NativeJet) -> Result<JetId, AdmitError> {
        if cert.cert_version != JET_CERT_VERSION {
            return Err(AdmitError::UnsupportedCertVersion(cert.cert_version));
        }
        if cert.compute_digest() != cert.digest {
            return Err(AdmitError::DigestMismatch);
        }
        let formula = decode_formula(&cert.formula).map_err(|_| AdmitError::MalformedFormula)?;
        let semantics = semantics_hash(&formula);
        if semantics != cert.semantics_hash {
            return Err(AdmitError::SemanticsHashMismatch);
        }
        if jet_id(&semantics, &cert.impl_tag) != cert.jet_id {
            return Err(AdmitError::JetIdMismatch);
        }
        let root = equivalence_root(
            &formula,
            native,
            cert.equivalence.corpus_seed,
            cert.equivalence.case_count,
        )
        .map_err(|case_index| AdmitError::EquivalenceDivergence { case_index })?;
        if root != cert.equivalence.corpus_root {
            return Err(AdmitError::EquivalenceRootMismatch);
        }
        let key = trim(&cert.jet_id.0).to_vec();
        if self.entries.contains_key(&key) {
            return Err(AdmitError::DuplicateJetId);
        }
        let id = cert.jet_id;
        self.entries.insert(key, JetEntry { cert, native });
        Ok(id)
    }
}

impl JetHook for JetRegistry {
    fn dispatch(
        &self,
        id: &Noun,
        subject: &Noun,
        formula: &Noun,
        meter: &mut Meter,
    ) -> Option<Result<Noun, GrainTrap>> {
        // A cell id or an unknown id declines: pure Grain interprets `f`.
        let key = id.as_atom()?;
        let entry = self.entries.get(key)?;
        // The offered formula must BE the certified semantics, exactly:
        // a certified id never fires on different semantics.
        if semantics_hash(formula) != entry.cert.semantics_hash {
            return None;
        }
        Some((entry.native)(subject, meter))
    }
}

/// Minimal little-endian view of a 32-byte digest (Noun atom key form).
fn trim(bytes: &[u8; 32]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| *b != 0)
        .map_or(0, |i| i.saturating_add(1));
    &bytes[..end]
}

/// One observational triple, encoded for hashing: value-or-trap, spent
/// steps, arena words.
fn interpret_triple(formula: &Noun, case: &corpus::Case) -> (Result<Vec<u8>, u16>, u64, u64) {
    let mut meter = Meter::new(case.step_limit, case.arena_limit);
    let r = eval(1, case.subject.clone(), formula.clone(), &mut meter);
    (
        r.map(|n| encode_noun(&n)).map_err(GrainTrap::code),
        meter.spent(),
        meter.arena_used(),
    )
}

fn native_triple(native: NativeJet, case: &corpus::Case) -> (Result<Vec<u8>, u16>, u64, u64) {
    let mut meter = Meter::new(case.step_limit, case.arena_limit);
    let r = native(&case.subject, &mut meter);
    (
        r.map(|n| encode_noun(&n)).map_err(GrainTrap::code),
        meter.spent(),
        meter.arena_used(),
    )
}

/// Replay the differential corpus: for every case, interpretation and the
/// native jet must produce identical triples. Returns the corpus root, or
/// the first diverging case index.
pub fn equivalence_root(
    formula: &Noun,
    native: NativeJet,
    seed: u64,
    case_count: u32,
) -> Result<[u8; 32], u32> {
    let mut h = blake3::Hasher::new();
    h.update(CTX_CORPUS);
    h.update(&seed.to_le_bytes());
    h.update(&case_count.to_le_bytes());
    for index in 0..case_count {
        let case = corpus::case(seed, index);
        let want = interpret_triple(formula, &case);
        let got = native_triple(native, &case);
        if want != got {
            return Err(index);
        }
        h.update(&index.to_le_bytes());
        h.update(&encode_noun(&case.subject));
        h.update(&case.step_limit.to_le_bytes());
        h.update(&case.arena_limit.to_le_bytes());
        match &want.0 {
            Ok(value) => {
                h.update(&[0u8]);
                h.update(value);
            }
            Err(code) => {
                h.update(&[1u8]);
                h.update(&code.to_le_bytes());
            }
        }
        h.update(&want.1.to_le_bytes());
        h.update(&want.2.to_le_bytes());
    }
    Ok(*h.finalize().as_bytes())
}
