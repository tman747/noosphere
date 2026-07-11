//! Proves the generated `DomainId` registry is byte-identical to the frozen
//! CSV: same rows, same order, same context strings, same kinds, same HKDF
//! salts; contexts pairwise distinct and prefix-free.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use noos_crypto::{DomainId, DomainKind, DOMAIN_COUNT};

const CSV: &str = include_str!("../../../protocol/spec/crypto-domains-v1.csv");

struct CsvRow<'a> {
    domain_id: &'a str,
    kind: &'a str,
    context: &'a str,
    salt: Option<&'a str>,
}

fn csv_rows() -> Vec<CsvRow<'static>> {
    let mut rows = Vec::new();
    for line in CSV.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') || line.starts_with("domain_id,") {
            continue;
        }
        let mut parts = line.splitn(6, ',');
        let domain_id = parts.next().expect("domain_id");
        let kind = parts.next().expect("kind");
        let context = parts.next().expect("context_string");
        let _algorithm = parts.next().expect("algorithm");
        let _consumer = parts.next().expect("consumer");
        let notes = parts.next().expect("notes");
        let salt = notes.split_once("salt=\"").map(|(_, rest)| {
            let end = rest.find('"').expect("terminated salt");
            &rest[..end]
        });
        rows.push(CsvRow {
            domain_id,
            kind,
            context,
            salt,
        });
    }
    rows
}

fn kind_of(csv_kind: &str) -> DomainKind {
    match csv_kind {
        "BLAKE3_CONTEXT" => DomainKind::Blake3Context,
        "BLAKE3_KEYED" => DomainKind::Blake3Keyed,
        "ED25519_PREFIX" => DomainKind::Ed25519Prefix,
        "BLS_DST" => DomainKind::BlsDst,
        "HKDF_INFO" => DomainKind::HkdfInfo,
        other => panic!("unknown CSV kind {other}"),
    }
}

#[test]
fn registry_is_identical_to_csv() {
    let rows = csv_rows();
    assert_eq!(rows.len(), DOMAIN_COUNT, "row count");
    assert_eq!(DomainId::ALL.len(), DOMAIN_COUNT);
    for (row, id) in rows.iter().zip(DomainId::ALL) {
        assert_eq!(id.registry_id(), row.domain_id);
        assert_eq!(id.context(), row.context, "{}", row.domain_id);
        assert_eq!(id.kind(), kind_of(row.kind), "{}", row.domain_id);
        assert_eq!(id.hkdf_salt(), row.salt, "{}", row.domain_id);
        assert_eq!(
            DomainId::from_registry_id(row.domain_id),
            Some(id),
            "{}",
            row.domain_id
        );
    }
    assert_eq!(DomainId::from_registry_id("D-NOT-A-DOMAIN"), None);
}

#[test]
fn contexts_are_distinct_and_prefix_free() {
    for a in DomainId::ALL {
        for b in DomainId::ALL {
            if a == b {
                continue;
            }
            assert_ne!(a.context(), b.context(), "{a:?} vs {b:?}");
            assert!(
                !b.context()
                    .as_bytes()
                    .starts_with(a.context().as_bytes()),
                "{a:?} context is a byte-prefix of {b:?}"
            );
        }
    }
}

#[test]
fn every_noos_context_carries_the_wire_namespace() {
    for id in DomainId::ALL {
        let context = id.context();
        assert!(
            context.starts_with("NOOS/") || context.starts_with("NOOS-BLS-"),
            "{id:?} context {context} escapes the NOOS namespace"
        );
    }
}

#[test]
fn hkdf_salts_exist_exactly_for_hkdf_rows() {
    for id in DomainId::ALL {
        assert_eq!(
            id.hkdf_salt().is_some(),
            id.kind() == DomainKind::HkdfInfo,
            "{id:?}"
        );
    }
}
