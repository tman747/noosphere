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
use noos_codec::{NoosDecode, NoosEncode};
use noos_crypto::{hash_domain, DomainId, DomainKind};
use noos_ground::GroundTicketV1;
use noos_lumen::fees::{self, Usage};
use noos_lumen::objects::{BoundedList, ReceiptV1, TransactionV1, TransactionWitnessesV1};

use crate::{Hash32, NodeError};

const DA_FORM_LZ4_MAGIC: &[u8; 8] = b"NOOSLZ41";
/// Fail-closed decompression ceiling for the canonical macroblock body.
pub const MAX_DA_FORM_RAW_BYTES: usize = 536_870_912;

fn ctx_root(domain: DomainId, bytes: &[u8]) -> Result<Hash32, NodeError> {
    Ok(hash_domain(domain, &[bytes])
        .map_err(|_| NodeError::Crypto)?
        .into_bytes())
}

fn canonical_list_root<T: NoosEncode>(domain: DomainId, items: &[T]) -> Result<Hash32, NodeError> {
    if domain.kind() != DomainKind::Blake3Context {
        return Err(NodeError::Crypto);
    }
    let count = u32::try_from(items.len()).map_err(|_| NodeError::BodyMismatch {
        what: "canonical list count exceeds u32",
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.context().as_bytes());
    hasher.update(&count.to_le_bytes());
    let mut writer = noos_codec::Writer::with_capacity(1024);
    for item in items {
        writer.clear();
        item.encode(&mut writer);
        hasher.update(writer.as_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

/// `tx_root` over the canonical ordered transaction list.
pub fn body_tx_root(
    txs: &BoundedList<TransactionV1, { noos_braid::MAX_TRANSACTIONS }>,
) -> Result<Hash32, NodeError> {
    canonical_list_root(DomainId::BodyTxRoot, txs.as_slice())
}

/// `witness_root` over the canonical ordered segregated-witness list
/// (positionally aligned with `transactions[]`).
pub fn body_witness_root(
    wits: &BoundedList<TransactionWitnessesV1, { noos_braid::MAX_SEGREGATED_WITNESSES }>,
) -> Result<Hash32, NodeError> {
    canonical_list_root(DomainId::BodyWitnessRoot, wits.as_slice())
}

/// `execution_receipt_root` over THIS block's ordered execution receipts
/// (plan §6.3: distinct from the post-state settled-receipt index).
pub fn body_receipt_root(receipts: &[ReceiptV1]) -> Result<Hash32, NodeError> {
    canonical_list_root(DomainId::BodyReceiptRoot, receipts)
}

/// `finality_certificate_root` over the canonical certificate list.
pub fn body_cert_root(
    certs: &BoundedList<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>,
) -> Result<Hash32, NodeError> {
    canonical_list_root(DomainId::BodyCertRoot, certs.as_slice())
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

/// The compressed DA body form (node-v1.md §3.2): canonical
/// `BlockBodyV1` bytes with `ground_ticket` canonicalized to
/// [`zero_ticket`], framed by `NOOSLZ41` and deterministic LZ4 block
/// compression. ch01 §4.3 fixes `proposal_commitment` (which includes
/// `body_da_root`) before the Ground nonce search, so the DA bytes remain
/// ticket-independent. The real ticket travels with the header and is bound
/// separately by `ground_ticket_root`.
#[must_use]
pub fn da_form_bytes(body: &noos_braid::BlockBodyV1) -> Vec<u8> {
    let canonical = body.encode_canonical_with_ground_ticket(zero_ticket());
    let compressed = lz4_flex::block::compress_prepend_size(&canonical);
    let mut framed = Vec::with_capacity(DA_FORM_LZ4_MAGIC.len().saturating_add(compressed.len()));
    framed.extend_from_slice(DA_FORM_LZ4_MAGIC);
    framed.extend_from_slice(&compressed);
    framed
}

/// Decode the only accepted DA form. Length is checked before allocation so a
/// forged compressed frame cannot exceed the 512 MiB canonical-body ceiling.
pub fn decode_da_form(bytes: &[u8]) -> Result<noos_braid::BlockBodyV1, NodeError> {
    let payload = bytes
        .strip_prefix(DA_FORM_LZ4_MAGIC)
        .ok_or(NodeError::BodyMismatch {
            what: "DA compression frame",
        })?;
    let size_bytes = payload.get(..4).ok_or(NodeError::BodyMismatch {
        what: "DA compression length",
    })?;
    let raw_len = u32::from_le_bytes(<[u8; 4]>::try_from(size_bytes).map_err(|_| {
        NodeError::BodyMismatch {
            what: "DA compression length",
        }
    })?) as usize;
    if raw_len > MAX_DA_FORM_RAW_BYTES {
        return Err(NodeError::BodyMismatch {
            what: "DA decompressed body limit",
        });
    }
    let canonical = lz4_flex::block::decompress_size_prepended(payload).map_err(|_| {
        NodeError::BodyMismatch {
            what: "DA decompression",
        }
    })?;
    if canonical.len() != raw_len {
        return Err(NodeError::BodyMismatch {
            what: "DA decompressed length",
        });
    }
    Ok(noos_braid::BlockBodyV1::decode_canonical(&canonical)?)
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
            total[i] = total[i].checked_add(u[i]).ok_or(NodeError::BodyMismatch {
                what: "gas total overflow",
            })?;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_da_form_is_deterministic_and_ticket_independent() {
        let body = noos_braid::vector_gen::minimal_body();
        let first = da_form_bytes(&body);
        let second = da_form_bytes(&body);
        assert_eq!(first, second);
        assert!(first.starts_with(DA_FORM_LZ4_MAGIC));

        let decoded = decode_da_form(&first).expect("valid compressed DA form");
        let mut expected = body;
        expected.ground_ticket = noos_braid::GroundTicketWire(zero_ticket());
        assert_eq!(decoded, expected);
    }

    #[test]
    fn compressed_da_form_rejects_corruption_and_oversized_claim() {
        let mut truncated = da_form_bytes(&noos_braid::vector_gen::minimal_body());
        truncated.pop();
        assert!(matches!(
            decode_da_form(&truncated),
            Err(NodeError::BodyMismatch {
                what: "DA decompression"
            })
        ));

        let mut oversized = DA_FORM_LZ4_MAGIC.to_vec();
        oversized.extend_from_slice(
            &u32::try_from(MAX_DA_FORM_RAW_BYTES + 1)
                .expect("ceiling fits u32")
                .to_le_bytes(),
        );
        assert!(matches!(
            decode_da_form(&oversized),
            Err(NodeError::BodyMismatch {
                what: "DA decompressed body limit"
            })
        ));
    }

    #[test]
    fn streaming_list_root_matches_canonical_list_bytes() {
        let items = [7_u64, 11, 13];
        let mut writer = noos_codec::Writer::new();
        writer.put_list(&items, items.len() as u32);
        let expected = hash_domain(DomainId::BodyTxRoot, &[writer.as_bytes()])
            .expect("registered body root domain")
            .into_bytes();
        assert_eq!(
            canonical_list_root(DomainId::BodyTxRoot, &items).expect("streaming root"),
            expected
        );
    }
}
