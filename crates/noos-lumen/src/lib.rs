//! NOOSPHERE Lumen: the typed authenticated public state (plan §4, arch §6/§11/§13.2).
//!
//! This crate is deliberately **storage-agnostic** (plan §4.1): it holds an
//! in-memory authenticated state, applies transactions against a bounded
//! copy-on-write overlay keyed by touched entries, and emits a canonical
//! ordered [`state::StateDelta`]. The later `noos-store` adapter turns that
//! delta into a WAL-backed RocksDB batch; no database behavior lives here.
//!
//! Law (frozen in `protocol/schemas/lumen-v1.md`):
//! - six state roots over a versioned depth-256 sparse Merkle tree ([`smt`]);
//! - exact object shapes per `protocol/spec/schema-tables/lumen-objects.md`
//!   ([`objects`]);
//! - the normative ten-step transaction application order (arch §6.6)
//!   implemented in [`state`];
//! - five-dimensional integer fees with bounded per-block controllers
//!   ([`fees`]);
//! - fixed-envelope issuance with no recreated missed/orphan emission and no
//!   useful-work mint path ([`issuance`]).
//!
//! No floats, checked arithmetic on every state path, deterministic iteration
//! (`BTreeMap` only), `unsafe` denied workspace-wide.

#![forbid(unsafe_code)]

pub mod engine;
pub mod fees;
pub mod issuance;
pub mod objects;
pub mod smt;
pub mod state;

#[doc(hidden)]
pub mod vector_gen;

#[cfg(test)]
mod state_tests;

/// 32-byte BLAKE3-256 digest / tree key. Plain array so it orders
/// lexicographically (= MSB-first bit order) in `BTreeMap`s.
pub type Hash32 = [u8; 32];

/// Registered BLAKE3 context strings consumed by Lumen
/// (`protocol/spec/crypto-domains-v1.csv`).
pub mod domains {
    /// D-NOTE-ID: `note_id = H(ctx || creating_txid || output_index_u32_le || canonical_note)`.
    pub const NOTE_ID: &str = "NOOS/NOTE/V1";
    /// D-TX-ID: txid over the canonical non-witness body.
    pub const TX_ID: &str = "NOOS/TX/ID/V1";
    /// D-TX-WID: wtxid over body + segregated witnesses.
    pub const TX_WID: &str = "NOOS/TX/WID/V1";
    /// D-SMT-LEAF: sparse-Merkle-tree leaf hash.
    pub const SMT_LEAF: &str = "NOOS/SMT/LEAF/V1";
    /// D-SMT-NODE: sparse-Merkle-tree internal node hash.
    pub const SMT_NODE: &str = "NOOS/SMT/NODE/V1";
    /// D-TX-WROOT: witness_root over the witness PROGRAM roots (lock
    /// reveals), signatures excluded — keeps the txid→signature binding
    /// acyclic.
    pub const TX_WROOT: &str = "NOOS/TX/WROOT/V1";
    /// D-OBJECT-ID:
    /// `object_id = H(ctx || creating_txid || action_index_u32_le || class_id_u32_le)`.
    pub const OBJECT_ID: &str = "NOOS/OBJECT/ID/V1";
}

/// Domain-bound BLAKE3-256: `H(context_string || parts[0] || parts[1] || ...)`.
///
/// Identical construction to `noos-crypto::hash_domain` (plan §3.3); when
/// noos-crypto lands, swapping this helper for the registry-checked API is a
/// byte-identical change.
#[must_use]
pub fn domain_hash(context: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(context.as_bytes());
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// Shared test utilities (test builds only): deterministic seeded PRNG and
/// the runtime-decoded legacy domain string used by identity-rejection tests.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
pub(crate) mod test_util {
    use crate::Hash32;

    /// Deterministic seeded PRNG (splitmix64) for property tests.
    pub(crate) struct SplitMix64(pub u64);

    impl SplitMix64 {
        pub(crate) fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        pub(crate) fn next_hash(&mut self) -> Hash32 {
            let mut h = [0u8; 32];
            for chunk in h.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            h
        }
    }

    /// Legacy note-domain string of the historical chain, hex-decoded at
    /// runtime: old-identity literals are forbidden in NOOSPHERE source
    /// (check_identity.py), so it must never appear as text here.
    pub(crate) fn legacy_note_domain() -> String {
        let hex = "415343454e542d4e4f54452d5631";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        String::from_utf8(bytes).unwrap()
    }
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn domain_separation_changes_digest() {
        let a = domain_hash(domains::SMT_LEAF, &[b"payload"]);
        let b = domain_hash(domains::SMT_NODE, &[b"payload"]);
        assert_ne!(
            a, b,
            "distinct contexts must never collide on equal payloads"
        );
    }

    #[test]
    fn old_identity_domain_never_matches() {
        // Cross-protocol identity boundary (plan §2.4): the historical
        // chain's note domain must produce a different digest for the same
        // payload. The legacy string is decoded from hex at runtime.
        let noos = domain_hash(domains::NOTE_ID, &[b"note-preimage"]);
        let legacy = test_util::legacy_note_domain();
        let old = domain_hash(&legacy, &[b"note-preimage"]);
        assert_ne!(noos, old);
    }
}
