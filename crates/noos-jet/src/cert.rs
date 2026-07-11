//! `JetCertV1`: the versioned jet-equivalence certificate (M-JET).
//!
//! A certificate binds, under one BLAKE3 digest:
//! - the **semantics hash** — BLAKE3 over the canonical noun bytes of the
//!   certified Grain formula (the slow relation IS the semantics);
//! - the **jet id** — derived from the semantics hash and a versioned
//!   implementation tag, so the same semantics with a different
//!   implementation is a different jet;
//! - the **equivalence record** — the seed, case count, and result root of
//!   the deterministic differential corpus replayed at admission.
//!
//! Nothing in a certificate is trusted as stated: admission re-derives every
//! field (see [`crate::registry::JetRegistry::admit`]). The digest is a
//! binding commitment, not an authority signature — forging it is easy,
//! surviving re-derivation is not.

use core::fmt;

use noos_grain::{encode_noun, Noun};

/// Certificate format version. Frozen; a new field set is a new version.
pub const JET_CERT_VERSION: u32 = 1;

// Frozen domain-separation contexts (prefix-unique within this crate).
const CTX_SEMANTICS: &[u8] = b"noosphere.jet.semantics.v1";
const CTX_JET_ID: &[u8] = b"noosphere.jet.id.v1";
const CTX_CERT: &[u8] = b"noosphere.jet.cert.v1";

/// BLAKE3-256 over `CTX_SEMANTICS || canonical-noun-bytes(formula)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticsHash(pub [u8; 32]);

/// BLAKE3-256 over `CTX_JET_ID || semantics_hash || len(tag) || tag`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JetId(pub [u8; 32]);

impl JetId {
    /// The id as a Grain atom for `[12 id f]` hints. Noun atoms are minimal
    /// little-endian bytes, so trailing zero digest bytes trim away; the
    /// trimmed form stays injective over fixed-length digests.
    #[must_use]
    pub fn as_noun(&self) -> Noun {
        Noun::atom_from_le_bytes(&self.0)
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

impl fmt::Debug for SemanticsHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SemanticsHash(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

impl fmt::Debug for JetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JetId(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// Semantics hash of a Grain formula: the canonical byte encoding is
/// self-contained, so this pins the exact slow relation.
#[must_use]
pub fn semantics_hash(formula: &Noun) -> SemanticsHash {
    let mut h = blake3::Hasher::new();
    h.update(CTX_SEMANTICS);
    h.update(&encode_noun(formula));
    SemanticsHash(*h.finalize().as_bytes())
}

/// Jet id: semantics plus versioned implementation identity.
#[must_use]
pub fn jet_id(semantics: &SemanticsHash, impl_tag: &str) -> JetId {
    let mut h = blake3::Hasher::new();
    h.update(CTX_JET_ID);
    h.update(&semantics.0);
    h.update(&u32_le(impl_tag.len()));
    h.update(impl_tag.as_bytes());
    JetId(*h.finalize().as_bytes())
}

/// The certified differential-equivalence record: replaying `case_count`
/// corpus cases from `corpus_seed` must reproduce `corpus_root` exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EquivalenceRecord {
    pub corpus_seed: u64,
    pub case_count: u32,
    pub corpus_root: [u8; 32],
}

/// Versioned jet certificate (M-JET `JetCert`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JetCert {
    pub cert_version: u32,
    pub jet_id: JetId,
    pub semantics_hash: SemanticsHash,
    /// Versioned implementation identity, e.g. `noos-jet/native/inc/v1`.
    pub impl_tag: String,
    /// Canonical noun bytes of the certified formula (self-contained).
    pub formula: Vec<u8>,
    pub equivalence: EquivalenceRecord,
    /// BLAKE3 commitment over every field above.
    pub digest: [u8; 32],
}

impl JetCert {
    /// Canonical byte serialization of everything the digest covers.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.cert_version.to_le_bytes());
        out.extend_from_slice(&self.jet_id.0);
        out.extend_from_slice(&self.semantics_hash.0);
        out.extend_from_slice(&u32_le(self.impl_tag.len()));
        out.extend_from_slice(self.impl_tag.as_bytes());
        out.extend_from_slice(&u32_le(self.formula.len()));
        out.extend_from_slice(&self.formula);
        out.extend_from_slice(&self.equivalence.corpus_seed.to_le_bytes());
        out.extend_from_slice(&self.equivalence.case_count.to_le_bytes());
        out.extend_from_slice(&self.equivalence.corpus_root);
        out
    }

    /// Recomputes the binding digest from the current field values.
    #[must_use]
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(CTX_CERT);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }
}

/// Length as a saturating u32 little-endian field (lengths here are tiny).
fn u32_le(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes()
}
