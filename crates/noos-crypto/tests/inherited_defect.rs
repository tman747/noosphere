//! Inherited-defect repair proof (baseline finding: `clippy::double_must_use`
//! on the port source's X25519 shared-secret function; see the historical
//! substrate BASELINE-REPORT.md under evidence/).
//!
//! Two guards:
//! 1. behavioral — the shared-secret contract: symmetry between both
//!    channel ends, contributory-behavior rejection of all-zero secrets
//!    from small-order peer points, and public-key determinism;
//! 2. structural — no `#[must_use]` attribute in this crate's sources
//!    directly decorates a `Result`-returning function (the exact
//!    double-must-use shape the baseline flagged).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use noos_crypto::{dkg_x25519_public_key, dkg_x25519_shared_secret, DkgError};
use std::fs;
use std::path::PathBuf;

#[test]
fn shared_secret_is_symmetric_and_deterministic() {
    let alice = [0x11_u8; 32];
    let bob = [0x22_u8; 32];
    let alice_pub = dkg_x25519_public_key(alice);
    let bob_pub = dkg_x25519_public_key(bob);
    assert_ne!(alice_pub, bob_pub);
    // Determinism.
    assert_eq!(alice_pub, dkg_x25519_public_key(alice));

    let ab = dkg_x25519_shared_secret(alice, bob_pub).unwrap();
    let ba = dkg_x25519_shared_secret(bob, alice_pub).unwrap();
    assert_eq!(ab, ba, "both channel ends must derive the same secret");
    assert_ne!(ab, [0_u8; 32]);

    // A different peer yields a different secret.
    let carol_pub = dkg_x25519_public_key([0x33_u8; 32]);
    let ac = dkg_x25519_shared_secret(alice, carol_pub).unwrap();
    assert_ne!(ab, ac);
}

#[test]
fn small_order_peer_points_are_rejected() {
    let secret = [0x42_u8; 32];
    // Identity point: shared secret is all-zero.
    let identity = [0_u8; 32];
    assert_eq!(
        dkg_x25519_shared_secret(secret, identity).unwrap_err(),
        DkgError::InvalidSharedSecret
    );
    // The order-2 point (u = 1): clamped scalar multiplication collapses
    // to the identity as well.
    let mut order_two = [0_u8; 32];
    order_two[0] = 1;
    assert_eq!(
        dkg_x25519_shared_secret(secret, order_two).unwrap_err(),
        DkgError::InvalidSharedSecret
    );
}

#[test]
fn no_bare_must_use_decorates_result_returning_functions() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0_usize;
    for entry in fs::read_dir(&src).expect("src dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable source");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() != "#[must_use]" {
                continue;
            }
            // Collect the signature that follows (attributes and the fn
            // header until its opening brace).
            let mut signature = String::new();
            for follow in lines.iter().skip(i + 1).take(8) {
                signature.push_str(follow);
                if follow.contains('{') {
                    break;
                }
            }
            checked += 1;
            assert!(
                !signature.contains("-> Result<"),
                "{}: bare #[must_use] on a Result-returning function \
                 (double_must_use, the inherited baseline defect):\n{signature}",
                path.display()
            );
        }
    }
    assert!(
        checked > 0,
        "expected at least one #[must_use] site to audit"
    );
}
