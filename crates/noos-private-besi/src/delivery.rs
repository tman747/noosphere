//! P4 / S-PAID-DELIVERY local contract: the request/escrow/input/model/output/delivery/payment/
//! independence bundle is the S-DEMAND classifier. Payment releases only when the delivery
//! ciphertext decrypts under the bundle's own binding AND the plaintext matches the committed
//! output. An undecryptable delivery is an explicit typed state (mirroring
//! `noos-commerce::DisableCause::UndecryptableDelivery`) and never pays. The classifier does not
//! prove model quality (non-claim).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use std::collections::BTreeSet;

pub const DELIVERY_DOMAIN: &[u8] = b"NOOS/BESI/PAID-DELIVERY/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryCiphertext {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// The named S-DEMAND bundle. Every field participates in classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemandBundle {
    pub request_id: [u8; 32],
    pub payer: [u8; 32],
    pub executors: [[u8; 32]; 2],
    pub escrow: u64,
    pub input_commitment: [u8; 32],
    pub model_root: [u8; 32],
    pub output_commitment: [u8; 32],
    pub delivery: DeliveryCiphertext,
    pub payouts: [u64; 2],
    pub declared_rebates: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaidDelivery {
    pub request_id: [u8; 32],
    pub payouts: [u64; 2],
}

/// Explicit typed classification faults. None of them release payment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryFault {
    /// The delivery does not decrypt under the bundle binding: explicit typed state, no payment.
    UndecryptableDelivery,
    /// The delivery decrypts but is not the committed output (undelivered/substituted output).
    UndeliveredOutput,
    /// The payer appears among the paid executors: wash billing.
    WashBilling,
    /// Payouts plus declared rebates do not conserve escrow: an undisclosed rebate exists.
    UndisclosedRebate,
    /// The request was already settled; payment is at most once.
    ReplayedRequest,
    Crypto,
}

fn binding_aad(bundle: &DemandBundle) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DELIVERY_DOMAIN.len().saturating_add(128));
    aad.extend_from_slice(DELIVERY_DOMAIN);
    aad.extend_from_slice(&bundle.request_id);
    aad.extend_from_slice(&bundle.model_root);
    aad.extend_from_slice(&bundle.input_commitment);
    aad.extend_from_slice(&bundle.output_commitment);
    aad
}

/// Producer-side helper: seal the delivered output to the bundle binding.
pub fn seal_delivery(
    bundle_without_delivery: &DemandBundle,
    delivery_key: &[u8; 32],
    output: &[u8],
) -> Result<DeliveryCiphertext, DeliveryFault> {
    let cipher = ChaCha20Poly1305::new(delivery_key.into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&bundle_without_delivery.request_id[..12]);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: output,
                aad: &binding_aad(bundle_without_delivery),
            },
        )
        .map_err(|_| DeliveryFault::Crypto)?;
    Ok(DeliveryCiphertext {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// At-most-once settlement ledger over the paid-delivery predicate.
#[derive(Clone, Debug, Default)]
pub struct SettlementLedger {
    settled: BTreeSet<[u8; 32]>,
}

impl SettlementLedger {
    /// The paid-delivery predicate. Order: replay, independence, conservation, decryptability,
    /// output binding. Only a fully classified bundle marks the request settled and pays.
    pub fn settle(
        &mut self,
        bundle: &DemandBundle,
        delivery_key: &[u8; 32],
    ) -> Result<PaidDelivery, DeliveryFault> {
        if self.settled.contains(&bundle.request_id) {
            return Err(DeliveryFault::ReplayedRequest);
        }
        if bundle.executors.contains(&bundle.payer) {
            return Err(DeliveryFault::WashBilling);
        }
        let paid = bundle.payouts[0]
            .checked_add(bundle.payouts[1])
            .and_then(|p| p.checked_add(bundle.declared_rebates));
        if paid != Some(bundle.escrow) {
            return Err(DeliveryFault::UndisclosedRebate);
        }
        let cipher = ChaCha20Poly1305::new(delivery_key.into());
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&bundle.delivery.nonce),
                Payload {
                    msg: bundle.delivery.ciphertext.as_slice(),
                    aad: &binding_aad(bundle),
                },
            )
            .map_err(|_| DeliveryFault::UndecryptableDelivery)?;
        if *blake3::hash(&plaintext).as_bytes() != bundle.output_commitment {
            return Err(DeliveryFault::UndeliveredOutput);
        }
        self.settled.insert(bundle.request_id);
        Ok(PaidDelivery {
            request_id: bundle.request_id,
            payouts: bundle.payouts,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const KEY: [u8; 32] = [42u8; 32];

    fn bundle(output: &[u8]) -> DemandBundle {
        let mut b = DemandBundle {
            request_id: [1u8; 32],
            payer: [2u8; 32],
            executors: [[3u8; 32], [4u8; 32]],
            escrow: 100,
            input_commitment: [5u8; 32],
            model_root: [6u8; 32],
            output_commitment: *blake3::hash(output).as_bytes(),
            delivery: DeliveryCiphertext {
                nonce: [0u8; 12],
                ciphertext: Vec::new(),
            },
            payouts: [60, 30],
            declared_rebates: 10,
        };
        b.delivery = seal_delivery(&b, &KEY, output).unwrap();
        b
    }

    #[test]
    fn decryptable_committed_delivery_pays_exactly_once() {
        let b = bundle(b"the delivered output");
        let mut ledger = SettlementLedger::default();
        let paid = ledger.settle(&b, &KEY).unwrap();
        assert_eq!(paid.payouts, [60, 30]);
        assert_eq!(ledger.settle(&b, &KEY), Err(DeliveryFault::ReplayedRequest));
    }

    #[test]
    fn falsifier_undecryptable_delivery_is_explicit_and_never_pays() {
        let mut b = bundle(b"the delivered output");
        let last = b.delivery.ciphertext.len() - 1;
        b.delivery.ciphertext[last] ^= 1;
        let mut ledger = SettlementLedger::default();
        assert_eq!(
            ledger.settle(&b, &KEY),
            Err(DeliveryFault::UndecryptableDelivery)
        );
        // No payment happened: the honest bundle still settles afterwards.
        let honest = bundle(b"the delivered output");
        assert!(ledger.settle(&honest, &KEY).is_ok());
    }

    #[test]
    fn falsifier_context_rebinding_is_undecryptable() {
        // Sealed under one model root, presented under another: AAD binding rejects.
        let mut b = bundle(b"the delivered output");
        b.model_root = [7u8; 32];
        let mut ledger = SettlementLedger::default();
        assert_eq!(
            ledger.settle(&b, &KEY),
            Err(DeliveryFault::UndecryptableDelivery)
        );
    }

    #[test]
    fn falsifier_undelivered_output_rejects() {
        // Decrypts fine but the plaintext is not the committed output.
        let mut b = bundle(b"something else entirely");
        b.output_commitment = *blake3::hash(b"the promised output").as_bytes();
        b.delivery = seal_delivery(&b, &KEY, b"something else entirely").unwrap();
        let mut ledger = SettlementLedger::default();
        assert_eq!(
            ledger.settle(&b, &KEY),
            Err(DeliveryFault::UndeliveredOutput)
        );
    }

    #[test]
    fn falsifier_wash_billing_rejects() {
        let mut b = bundle(b"the delivered output");
        b.payer = b.executors[1];
        let mut ledger = SettlementLedger::default();
        assert_eq!(ledger.settle(&b, &KEY), Err(DeliveryFault::WashBilling));
    }

    #[test]
    fn falsifier_undisclosed_rebate_rejects() {
        let mut b = bundle(b"the delivered output");
        // 60 + 30 + 5 != 100: five units moved off the books.
        b.declared_rebates = 5;
        let mut ledger = SettlementLedger::default();
        assert_eq!(
            ledger.settle(&b, &KEY),
            Err(DeliveryFault::UndisclosedRebate)
        );
        // Overflow attempts also fail closed.
        b.payouts = [u64::MAX, 1];
        b.declared_rebates = 0;
        assert_eq!(
            ledger.settle(&b, &KEY),
            Err(DeliveryFault::UndisclosedRebate)
        );
    }
}
