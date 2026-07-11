//! A-UMBRA-BASE stealth envelopes: notes are sealed to a recipient scan key via an ephemeral
//! X25519 exchange. A one-byte view tag lets the scanner reject foreign envelopes with a single
//! hash and no AEAD work (scanner-DoS bound); decryption requires the per-recipient scan secret,
//! so no universal viewing path exists. Wrong-recipient scans classify as `NotMine`; any
//! tampering with the ephemeral key, tag, or ciphertext rejects.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const STEALTH_DOMAIN: &[u8] = b"NOOS/UMBRA/STEALTH-ENVELOPE/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StealthError {
    /// Authenticated decryption failed: the envelope was tampered with or misdirected.
    Envelope,
    Derive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StealthEnvelope {
    pub ephemeral: [u8; 32],
    pub view_tag: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// (note key, view tag) from the Diffie-Hellman shared secret, domain separated.
fn derive_note_key(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
) -> Result<([u8; 32], u8), StealthError> {
    let hk = Hkdf::<Sha256>::new(Some(STEALTH_DOMAIN), shared);
    let mut okm = [0u8; 33];
    hk.expand(ephemeral, &mut okm)
        .map_err(|_| StealthError::Derive)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    Ok((key, okm[32]))
}

/// Sender side: seals `note` to the recipient's scan public key with a fresh ephemeral secret.
pub fn seal(
    recipient_scan_public: &PublicKey,
    ephemeral_secret: StaticSecret,
    nonce: [u8; 12],
    note: &[u8],
) -> Result<StealthEnvelope, StealthError> {
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient_scan_public);
    let (key, view_tag) = derive_note_key(shared.as_bytes(), ephemeral_public.as_bytes())?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: note,
                aad: ephemeral_public.as_bytes(),
            },
        )
        .map_err(|_| StealthError::Envelope)?;
    Ok(StealthEnvelope {
        ephemeral: *ephemeral_public.as_bytes(),
        view_tag,
        nonce,
        ciphertext,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanOutcome {
    /// The cheap view-tag prefilter rejected the envelope: no AEAD work was spent.
    NotMine,
    Note(Vec<u8>),
}

/// Scanner side: one DH + one KDF decides `NotMine`; only tag matches pay for AEAD.
pub fn scan(
    scan_secret: &StaticSecret,
    envelope: &StealthEnvelope,
) -> Result<ScanOutcome, StealthError> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral);
    let shared = scan_secret.diffie_hellman(&ephemeral_public);
    let (key, view_tag) = derive_note_key(shared.as_bytes(), &envelope.ephemeral)?;
    if view_tag != envelope.view_tag {
        return Ok(ScanOutcome::NotMine);
    }
    let cipher = ChaCha20Poly1305::new(&key.into());
    let note = cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: envelope.ciphertext.as_slice(),
                aad: &envelope.ephemeral,
            },
        )
        .map_err(|_| StealthError::Envelope)?;
    Ok(ScanOutcome::Note(note))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn recipient() -> StaticSecret {
        StaticSecret::from([11u8; 32])
    }

    fn sealed_note() -> StealthEnvelope {
        let scan_public = PublicKey::from(&recipient());
        seal(
            &scan_public,
            StaticSecret::from([22u8; 32]),
            [1u8; 12],
            b"a private note",
        )
        .unwrap()
    }

    #[test]
    fn recipient_detects_and_opens_the_note() {
        let envelope = sealed_note();
        assert_eq!(
            scan(&recipient(), &envelope),
            Ok(ScanOutcome::Note(b"a private note".to_vec()))
        );
    }

    #[test]
    fn falsifier_no_universal_viewing_path() {
        // Neither another recipient nor a would-be network-wide key opens the envelope; the
        // note is bound to the one scan secret used at sealing.
        let envelope = sealed_note();
        for wrong in [
            StaticSecret::from([33u8; 32]),
            StaticSecret::from([0u8; 32]),
            StaticSecret::from([0xFFu8; 32]),
        ] {
            match scan(&wrong, &envelope) {
                // Almost always the cheap tag prefilter rejects.
                Ok(ScanOutcome::NotMine) => {}
                // A 1/256 tag collision still fails authenticated decryption.
                Err(StealthError::Envelope) => {}
                other => panic!("wrong key must never open a note, got {other:?}"),
            }
        }
    }

    #[test]
    fn falsifier_tampered_envelope_rejects() {
        let mut tampered = sealed_note();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 1;
        assert_eq!(scan(&recipient(), &tampered), Err(StealthError::Envelope));
        // Substituting the ephemeral key breaks both the derived key and the AAD binding.
        let mut substituted = sealed_note();
        substituted.ephemeral = *PublicKey::from(&StaticSecret::from([44u8; 32])).as_bytes();
        match scan(&recipient(), &substituted) {
            Ok(ScanOutcome::NotMine) | Err(StealthError::Envelope) => {}
            other => panic!("substituted ephemeral must not open, got {other:?}"),
        }
    }

    #[test]
    fn view_tag_prefilter_short_circuits_before_aead() {
        // Flipping only the view tag classifies as NotMine (cheap reject path) even though the
        // ciphertext itself is intact: the scanner never spends AEAD work on it.
        let mut envelope = sealed_note();
        envelope.view_tag ^= 0xA5;
        assert_eq!(scan(&recipient(), &envelope), Ok(ScanOutcome::NotMine));
    }

    #[test]
    fn distinct_ephemerals_unlink_envelopes_to_the_same_recipient() {
        let scan_public = PublicKey::from(&recipient());
        let a = seal(
            &scan_public,
            StaticSecret::from([50u8; 32]),
            [1u8; 12],
            b"n",
        )
        .unwrap();
        let b = seal(
            &scan_public,
            StaticSecret::from([51u8; 32]),
            [1u8; 12],
            b"n",
        )
        .unwrap();
        // Same note, same recipient: everything observable differs per ephemeral.
        assert_ne!(a.ephemeral, b.ephemeral);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
