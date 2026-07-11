//! Chain-identity binding for the transport handshake (p2p-v1.md §5).
//!
//! libp2p QUIC's TLS layer authenticates the remote Ed25519 key (certificate
//! pinning: the libp2p certificate extension binds the connection to the peer
//! identity key, and dialing by `PeerId` pins the expected key). It does NOT
//! bind chain identity — that behavior is added here around libp2p: an
//! attestation signed under D-SIG-PEER over
//! `(chain_id, genesis_hash, protocol_version, peer_pubkey)` is exchanged on
//! `/noos/handshake/1` before any application protocol traffic.

use crate::envelope::{Bytes64, ChainAttestationV1, RejectCode};
use noos_crypto::{verify_domain, DomainId, Keypair, PublicKey, Signature};

/// The local chain identity every session must attest to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIdentity {
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub protocol_version: u16,
}

/// Signs a chain attestation for `keypair` (the same Ed25519 key that backs
/// the libp2p TLS identity).
pub fn sign_attestation(identity: &ChainIdentity, keypair: &Keypair) -> ChainAttestationV1 {
    let peer_pubkey = keypair.public_key().into_bytes();
    let version_le = identity.protocol_version.to_le_bytes();
    let signature = keypair
        .sign_domain(
            DomainId::SigPeer,
            &[
                &identity.chain_id,
                &identity.genesis_hash,
                &version_le,
                &peer_pubkey,
            ],
        )
        // D-SIG-PEER is a registered ED25519_PREFIX row.
        .unwrap_or_else(|_| unreachable!("D-SIG-PEER is a registered Ed25519 domain"));
    ChainAttestationV1 {
        chain_id: identity.chain_id,
        genesis_hash: identity.genesis_hash,
        protocol_version: identity.protocol_version,
        peer_pubkey,
        signature: Bytes64(signature.into_bytes()),
    }
}

/// Validates a remote attestation against the local chain identity and the
/// TLS-authenticated remote Ed25519 public key.
///
/// Order of laws (identity-v1.md §5): wrong chain identity rejects FIRST —
/// before signature work — with `wrong_protocol_identity`; only a
/// chain-matching attestation earns signature verification.
pub fn verify_attestation(
    identity: &ChainIdentity,
    tls_authenticated_pubkey: &[u8; 32],
    attestation: &ChainAttestationV1,
) -> Result<(), RejectCode> {
    if attestation.chain_id != identity.chain_id
        || attestation.genesis_hash != identity.genesis_hash
        || attestation.protocol_version != identity.protocol_version
    {
        return Err(RejectCode::WrongProtocolIdentity);
    }
    if &attestation.peer_pubkey != tls_authenticated_pubkey {
        return Err(RejectCode::AttestationInvalid);
    }
    let key = PublicKey::from_bytes(attestation.peer_pubkey);
    let sig = Signature::from_bytes(attestation.signature.0);
    let version_le = attestation.protocol_version.to_le_bytes();
    verify_domain(
        DomainId::SigPeer,
        &key,
        &[
            &attestation.chain_id,
            &attestation.genesis_hash,
            &version_le,
            &attestation.peer_pubkey,
        ],
        &sig,
    )
    .map_err(|_| RejectCode::AttestationInvalid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn identity() -> ChainIdentity {
        ChainIdentity {
            chain_id: [0x11; 32],
            genesis_hash: [0x22; 32],
            protocol_version: 1,
        }
    }

    fn keypair() -> Keypair {
        Keypair::from_seed([0x33; 32])
    }

    #[test]
    fn valid_attestation_verifies() {
        let kp = keypair();
        let att = sign_attestation(&identity(), &kp);
        let tls_key = kp.public_key().into_bytes();
        assert_eq!(verify_attestation(&identity(), &tls_key, &att), Ok(()));
    }

    #[test]
    fn wrong_chain_rejects_with_wrong_protocol_identity_before_signature() {
        let kp = keypair();
        let mut att = sign_attestation(&identity(), &kp);
        let tls_key = kp.public_key().into_bytes();

        att.chain_id = [0xFF; 32];
        // Signature is now stale too, but the identity check MUST fire first.
        assert_eq!(
            verify_attestation(&identity(), &tls_key, &att),
            Err(RejectCode::WrongProtocolIdentity)
        );

        let mut att = sign_attestation(&identity(), &kp);
        att.genesis_hash = [0xFF; 32];
        assert_eq!(
            verify_attestation(&identity(), &tls_key, &att),
            Err(RejectCode::WrongProtocolIdentity)
        );

        let mut att = sign_attestation(&identity(), &kp);
        att.protocol_version = 2;
        assert_eq!(
            verify_attestation(&identity(), &tls_key, &att),
            Err(RejectCode::WrongProtocolIdentity)
        );
    }

    #[test]
    fn tls_key_mismatch_rejects() {
        let kp = keypair();
        let att = sign_attestation(&identity(), &kp);
        let other = Keypair::from_seed([0x44; 32]).public_key().into_bytes();
        assert_eq!(
            verify_attestation(&identity(), &other, &att),
            Err(RejectCode::AttestationInvalid)
        );
    }

    #[test]
    fn tampered_signature_rejects() {
        let kp = keypair();
        let mut att = sign_attestation(&identity(), &kp);
        att.signature.0[0] ^= 1;
        let tls_key = kp.public_key().into_bytes();
        assert_eq!(
            verify_attestation(&identity(), &tls_key, &att),
            Err(RejectCode::AttestationInvalid)
        );
    }

    #[test]
    fn attestation_from_wrong_key_rejects() {
        // Signed by A but claiming B's pubkey: the self-consistency check on
        // peer_pubkey vs TLS key passes only for B, and then the signature
        // fails under B's key.
        let a = keypair();
        let b = Keypair::from_seed([0x55; 32]);
        let mut att = sign_attestation(&identity(), &a);
        att.peer_pubkey = b.public_key().into_bytes();
        let tls_key = b.public_key().into_bytes();
        assert_eq!(
            verify_attestation(&identity(), &tls_key, &att),
            Err(RejectCode::AttestationInvalid)
        );
    }
}
