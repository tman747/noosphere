//! Devnet fixture witness set (TEST NETWORKS ONLY).
//!
//! The devnet parameter file declares a deterministic local DKG fixture in
//! place of the multi-party ceremony (`[dkg] is_test_fixture = true`). This
//! module is that fixture's runtime half: the frozen witness bonds backing
//! the devnet epoch snapshot registry, and the seed law binding each fixture
//! member to its BLS signing seed.
//!
//! Fixture laws (frozen; tests and the `noosd --validator` devnet loop share
//! them byte for byte):
//! * `validator_id(i) = [(i + 1); 32]`
//! * BLS seed          = the validator id bytes themselves
//! * withdrawal key    = Ed25519 from seed `[(0x81 + i); 32]`
//!
//! The fixture-refusal law (plan §2.5) keeps this material off mainnet:
//! `noosd` only installs these bonds when the loaded parameters set
//! `is_test_network = true`, and every parameter file carrying fixtures on a
//! non-test network is refused at parse time.

use noos_braid::Bytes48;
use noos_crypto::{BlsSecretKey, Keypair};
use noos_lumen::objects::BoundedBytes;
use noos_witness::bond::WitnessBondV1;

use crate::{Hash32, NodeError};

/// Devnet fixture bond above the devnet minimum (valueless NOOS_TEST).
pub const FIXTURE_BOND_MICRO: u128 = 5_000_000_000_000;

/// Fixture validator id `i` (0-based): `[(i + 1); 32]`.
#[must_use]
pub fn fixture_validator_id(i: usize) -> Hash32 {
    [(i as u8).wrapping_add(1); 32]
}

/// BLS signing secret for fixture member `i`: seed = validator id bytes.
///
/// # Errors
/// [`noos_crypto`] seed rejection (never for the fixture ids).
pub fn fixture_witness_secret(i: usize) -> Result<BlsSecretKey, noos_crypto::BlsError> {
    BlsSecretKey::from_seed(fixture_validator_id(i))
}

/// The `n`-member devnet fixture witness set with real BLS keys.
///
/// # Errors
/// [`NodeError::Crypto`] when a fixture seed is rejected by the BLS
/// key-generation path (never for the frozen fixture ids).
pub fn fixture_witness_bonds(n: usize) -> Result<Vec<WitnessBondV1>, NodeError> {
    (0..n)
        .map(|i| {
            let secret = fixture_witness_secret(i).map_err(|_| NodeError::Crypto)?;
            let ed = Keypair::from_seed([0x81_u8.wrapping_add(i as u8); 32]);
            Ok(WitnessBondV1 {
                validator_id: fixture_validator_id(i),
                consensus_bls_key: Bytes48(secret.public_key().into_bytes()),
                withdrawal_key: ed.public_key().into_bytes(),
                network_endpoints_commitment: [0x11; 32],
                failure_domains: BoundedBytes::new(vec![b'd', i as u8]).ok_or(NodeError::Crypto)?,
                bonded_noos: FIXTURE_BOND_MICRO,
                activation_epoch: 0,
                exit_epoch: 0,
                proofpower_account: [0x22; 32],
            })
        })
        .collect()
}
