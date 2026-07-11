//! `WitnessBondV1` and registration validity (witness-v1.md §1.1; ch01 §4.6).
//!
//! Wire layout: versioned mandatory-tagged noos-codec object; the leading
//! canonical `u16` version is followed by the nine schema fields as
//! `tag:u16 || value` with tags `1..=9` in schema order 0..8.
//!
//! Registration validity (§1.1):
//! * the 32-byte Ed25519 withdrawal key MUST differ from the consensus key
//!   material — rejected if it appears as ANY contiguous 32-byte window of
//!   the 48-byte compressed BLS key;
//! * BLS proof of possession under the `D-BLS-POP` DST;
//! * Ed25519 self-signature by the withdrawal key under the
//!   `NOOS/SIG/TX/V1` context over the canonical bond bytes;
//! * `exit_epoch` is `0` while active, otherwise strictly after
//!   `activation_epoch`.
//!
//! Duplicate consensus keys and conflicting (duplicate-`validator_id`)
//! declarations are SET-level invalidity, enforced at membership intake
//! ([`crate::membership::build_snapshot`]).
//!
//! "Bond locked before the `e-2` snapshot" is a membership-time predicate:
//! the deterministic candidate list is read from finalized `e-2` state only
//! (§2), so a later bond simply cannot appear in it.

use noos_braid::{Bytes48, Bytes96};
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};
use noos_crypto::{bls_pop_verify, verify_domain, BlsPublicKey, DomainId, PublicKey, Signature};
use noos_lumen::objects::BoundedBytes;

use crate::WitnessError;

/// Maximum declared failure-domain bytes (witness-v1.md §1.1 field 4).
pub const MAX_FAILURE_DOMAIN_BYTES: u32 = 1024;

/// Ed25519 signature bytes, raw fixed width on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bytes64(pub [u8; 64]);

impl core::fmt::Debug for Bytes64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Bytes64(..)")
    }
}

impl NoosEncode for Bytes64 {
    fn encode(&self, w: &mut Writer) {
        w.put_raw(&self.0);
    }
}

impl NoosDecode for Bytes64 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut out = [0_u8; 64];
        for chunk in out.chunks_mut(32) {
            chunk.copy_from_slice(&r.get_array32()?);
        }
        Ok(Self(out))
    }
}

define_object! {
    /// The nine-field witness bond (witness-v1.md §1.1).
    pub struct WitnessBondV1 {
        version: 1;
        1 => validator_id: [u8; 32],
        2 => consensus_bls_key: Bytes48,
        3 => withdrawal_key: [u8; 32],
        4 => network_endpoints_commitment: [u8; 32],
        5 => failure_domains: BoundedBytes<MAX_FAILURE_DOMAIN_BYTES>,
        6 => bonded_noos: u128,
        7 => activation_epoch: u64,
        8 => exit_epoch: u64,
        9 => proofpower_account: [u8; 32],
    }
}

impl WitnessBondV1 {
    /// Active-at-epoch predicate: `activation_epoch ≤ e < exit_epoch`, with
    /// `exit_epoch = 0` meaning "no scheduled exit" (§1.1 field 7).
    #[must_use]
    pub fn active_at(&self, epoch: u64) -> bool {
        self.activation_epoch <= epoch && (self.exit_epoch == 0 || epoch < self.exit_epoch)
    }
}

define_object! {
    /// A bond registration: the bond plus BOTH possession proofs (§1.1).
    pub struct BondRegistrationV1 {
        version: 1;
        1 => bond: WitnessBondV1,
        2 => bls_possession_proof: Bytes96,
        3 => withdrawal_self_signature: Bytes64,
    }
}

/// Whether the 32-byte withdrawal key occurs as a contiguous window of the
/// 48-byte compressed consensus key ("MUST differ from consensus key
/// material", §1.1).
#[must_use]
fn key_material_overlaps(consensus: &[u8; 48], withdrawal: &[u8; 32]) -> bool {
    consensus.windows(32).any(|w| w == withdrawal)
}

/// Full single-registration validity (§1.1). Set-level checks (duplicate
/// consensus keys, conflicting declarations) live at membership intake.
pub fn validate_registration(reg: &BondRegistrationV1) -> Result<(), WitnessError> {
    let bond = &reg.bond;

    if key_material_overlaps(&bond.consensus_bls_key.0, &bond.withdrawal_key) {
        return Err(WitnessError::KeyMaterialOverlap);
    }
    if bond.exit_epoch != 0 && bond.exit_epoch <= bond.activation_epoch {
        return Err(WitnessError::MalformedExitEpoch);
    }

    // BLS proof of possession: the consensus key signs its own compressed
    // bytes under D-BLS-POP.
    let bls_key = BlsPublicKey::from_bytes(bond.consensus_bls_key.0);
    let pop = noos_crypto::BlsSignature::from_bytes(reg.bls_possession_proof.0);
    bls_pop_verify(&bls_key, &pop).map_err(|_| WitnessError::PossessionProofInvalid)?;

    // Ed25519 self-signature under NOOS/SIG/TX/V1 over the canonical bond.
    let ed_key = PublicKey::from_bytes(bond.withdrawal_key);
    let sig = Signature::from_bytes(reg.withdrawal_self_signature.0);
    verify_domain(DomainId::SigTx, &ed_key, &[&bond.encode_canonical()], &sig)
        .map_err(|_| WitnessError::SelfSignatureInvalid)?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use noos_crypto::{bls_pop_prove, BlsSecretKey, Keypair};

    pub(crate) fn signed_registration(seed: u8) -> BondRegistrationV1 {
        let bls_secret = BlsSecretKey::from_seed([seed; 32]).unwrap();
        let ed = Keypair::from_seed([seed.wrapping_add(0x80); 32]);
        let bond = WitnessBondV1 {
            validator_id: [seed; 32],
            consensus_bls_key: Bytes48(bls_secret.public_key().into_bytes()),
            withdrawal_key: ed.public_key().into_bytes(),
            network_endpoints_commitment: [0x11; 32],
            failure_domains: BoundedBytes::new(vec![seed, 1, 2]).unwrap(),
            bonded_noos: 5_000_000_000,
            activation_epoch: 0,
            exit_epoch: 0,
            proofpower_account: [0x22; 32],
        };
        let sig = ed
            .sign_domain(DomainId::SigTx, &[&bond.encode_canonical()])
            .unwrap();
        BondRegistrationV1 {
            bond,
            bls_possession_proof: Bytes96(bls_pop_prove(&bls_secret).unwrap().into_bytes()),
            withdrawal_self_signature: Bytes64(sig.into_bytes()),
        }
    }

    #[test]
    fn valid_registration_passes() {
        assert_eq!(validate_registration(&signed_registration(7)), Ok(()));
    }

    #[test]
    fn bond_roundtrips_canonically() {
        let reg = signed_registration(3);
        let bytes = reg.encode_canonical();
        let back = BondRegistrationV1::decode_canonical(&bytes).unwrap();
        assert_eq!(back, reg);
    }

    #[test]
    fn withdrawal_key_embedded_in_consensus_key_rejects() {
        let mut reg = signed_registration(9);
        // Plant the withdrawal key at window offset 5 of the BLS key bytes.
        let wk = reg.bond.withdrawal_key;
        reg.bond.consensus_bls_key.0[5..37].copy_from_slice(&wk);
        assert_eq!(
            validate_registration(&reg),
            Err(WitnessError::KeyMaterialOverlap)
        );
    }

    #[test]
    fn wrong_pop_rejects() {
        let mut reg = signed_registration(4);
        reg.bls_possession_proof.0[0] ^= 0x01;
        assert_eq!(
            validate_registration(&reg),
            Err(WitnessError::PossessionProofInvalid)
        );
    }

    #[test]
    fn pop_from_another_key_rejects() {
        let a = signed_registration(4);
        let mut b = signed_registration(5);
        b.bls_possession_proof = a.bls_possession_proof;
        assert_eq!(
            validate_registration(&b),
            Err(WitnessError::PossessionProofInvalid)
        );
    }

    #[test]
    fn tampered_bond_breaks_self_signature() {
        let mut reg = signed_registration(6);
        reg.bond.bonded_noos ^= 1;
        assert_eq!(
            validate_registration(&reg),
            Err(WitnessError::SelfSignatureInvalid)
        );
    }

    #[test]
    fn exit_epoch_not_after_activation_rejects() {
        let mut reg = signed_registration(8);
        reg.bond.activation_epoch = 10;
        reg.bond.exit_epoch = 10;
        // Re-sign so only the exit rule fires.
        let ed = Keypair::from_seed([8_u8.wrapping_add(0x80); 32]);
        reg.withdrawal_self_signature = Bytes64(
            ed.sign_domain(DomainId::SigTx, &[&reg.bond.encode_canonical()])
                .unwrap()
                .into_bytes(),
        );
        assert_eq!(
            validate_registration(&reg),
            Err(WitnessError::MalformedExitEpoch)
        );
    }

    #[test]
    fn activity_window_law() {
        let mut bond = signed_registration(2).bond;
        bond.activation_epoch = 5;
        bond.exit_epoch = 8;
        assert!(!bond.active_at(4));
        assert!(bond.active_at(5));
        assert!(bond.active_at(7));
        assert!(!bond.active_at(8));
        bond.exit_epoch = 0;
        assert!(bond.active_at(u64::MAX));
    }
}
