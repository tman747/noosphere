//! Header body-root binding law (node-v1.md §3; `D-BODY-*` registry rows).
//!
//! `noos-braid` freezes the header WIRE but leaves the body-derived roots
//! semantically open; this module is the binding law the node enforces in
//! import stage 3 (body/header cross-check) and uses in block production:
//!
//! ```text
//! tx_root                    = H(D-BODY-TX-ROOT      || canonical transactions list)
//! witness_root               = H(D-BODY-WITNESS-ROOT || canonical segregated_witnesses list)
//! execution_receipt_root     = H(D-BODY-RECEIPT-ROOT || canonical ordered ReceiptV1 list)
//! finality_certificate_root  = H(D-BODY-CERT-ROOT    || canonical finality_certificates list)
//! ground_ticket_root         = H(D-BODY-TICKET-ROOT  || canonical 76-byte ticket)
//! evidence_root              = ZERO_ROOT   (evidence lane unfrozen; fail closed)
//! ```
//!
//! `lumen_receipts_state_root` is NOT computed here: it is the post-state
//! projection of `LumenState.receipts_root` and comes from the transition.

use noos_braid::{BlobDescriptorV1, FinalityCertificateV1, MAX_FINALITY_CERTIFICATES};
use noos_codec::NoosEncode;
use noos_crypto::{hash_domain, DomainId};
use noos_ground::GroundTicketV1;
use noos_lumen::fees::{self, Usage};
use noos_lumen::objects::{BoundedList, ReceiptV1, TransactionV1, TransactionWitnessesV1};

use crate::{Hash32, NodeError};

fn ctx_root(domain: DomainId, bytes: &[u8]) -> Result<Hash32, NodeError> {
    Ok(hash_domain(domain, &[bytes])
        .map_err(|_| NodeError::Crypto)?
        .into_bytes())
}

/// `tx_root` over the canonical ordered transaction list.
pub fn body_tx_root(
    txs: &BoundedList<TransactionV1, { noos_braid::MAX_TRANSACTIONS }>,
) -> Result<Hash32, NodeError> {
    ctx_root(DomainId::BodyTxRoot, &txs.encode_canonical())
}

/// `witness_root` over the canonical ordered segregated-witness list
/// (positionally aligned with `transactions[]`).
pub fn body_witness_root(
    wits: &BoundedList<TransactionWitnessesV1, { noos_braid::MAX_SEGREGATED_WITNESSES }>,
) -> Result<Hash32, NodeError> {
    ctx_root(DomainId::BodyWitnessRoot, &wits.encode_canonical())
}

/// `execution_receipt_root` over THIS block's ordered execution receipts
/// (plan §6.3: distinct from the post-state settled-receipt index).
pub fn body_receipt_root(receipts: &[ReceiptV1]) -> Result<Hash32, NodeError> {
    let mut w = noos_codec::Writer::with_capacity(64 + receipts.len() * 96);
    w.put_u32(u32::try_from(receipts.len()).map_err(|_| NodeError::BodyMismatch {
        what: "receipt count exceeds u32",
    })?);
    for r in receipts {
        w.put_raw(&r.encode_canonical());
    }
    ctx_root(DomainId::BodyReceiptRoot, w.as_bytes())
}

/// `finality_certificate_root` over the canonical certificate list.
pub fn body_cert_root(
    certs: &BoundedList<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>,
) -> Result<Hash32, NodeError> {
    ctx_root(DomainId::BodyCertRoot, &certs.encode_canonical())
}

/// `ground_ticket_root` over the canonical 76-byte ticket.
pub fn body_ticket_root(ticket: &GroundTicketV1) -> Result<Hash32, NodeError> {
    ctx_root(DomainId::BodyTicketRoot, &ticket.encode())
}

/// The all-zero pre-search ticket that canonicalizes the DA body form.
#[must_use]
pub fn zero_ticket() -> GroundTicketV1 {
    GroundTicketV1 {
        profile_id: 0,
        nonce: 0,
        extra_nonce: [0; 32],
        digest: noos_crypto::Hash32::ZERO,
    }
}

/// The DA body form (node-v1.md §3.2): canonical `BlockBodyV1` bytes with
/// `ground_ticket` canonicalized to [`zero_ticket`]. ch01 §4.3 fixes
/// `proposal_commitment` (which includes `body_da_root`) BEFORE the Ground
/// nonce search, so the DA-committed bytes MUST be ticket-independent; the
/// real ticket travels with the header and is bound by `ground_ticket_root`
/// (header field 24, the one root excluded from the commitment) plus the
/// ticket law itself.
#[must_use]
pub fn da_form_bytes(body: &noos_braid::BlockBodyV1) -> Vec<u8> {
    let mut form = body.clone();
    form.ground_ticket = noos_braid::GroundTicketWire(zero_ticket());
    form.encode_canonical()
}

/// Blob-descriptor validation for consensus bodies (delegated to noos-da's
/// closed registries); v1 bodies carry no descriptors, so any entry is
/// checked and then refused as unfrozen application traffic.
pub fn check_blob_descriptors(descriptors: &[BlobDescriptorV1]) -> Result<(), NodeError> {
    for d in descriptors {
        noos_da::validate_consensus_blob_descriptor(d)?;
    }
    Ok(())
}

/// Sums per-receipt resource usage into the header's five-axis
/// `gas_used` vector (B, G, V, R, D), checked.
pub fn sum_usage(receipts: &[ReceiptV1]) -> Result<Usage, NodeError> {
    let mut total: Usage = [0; fees::DIMENSIONS];
    for r in receipts {
        let u = fees::usage_from_resources(&r.resources_used);
        for i in 0..fees::DIMENSIONS {
            total[i] = total[i]
                .checked_add(u[i])
                .ok_or(NodeError::BodyMismatch { what: "gas total overflow" })?;
        }
    }
    Ok(total)
}
