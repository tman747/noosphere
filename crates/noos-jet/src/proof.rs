//! Proof dispatch: binding lowered RV32 images to proof requests, and the
//! receipt-verification interface.
//!
//! A [`ProofRequest`] names WHAT must be proven — an exact [`Rv32Image`]
//! image id, an input commitment, and a journal commitment — independently
//! of HOW it is proven. [`LocalExecutionChecker`] is the deterministic
//! non-production implementation of [`ReceiptVerifier`]: it re-executes the
//! pinned image and rejects on any mismatch. Re-execution is exact, so it has zero false
//! accepts by construction — but it is NOT succinct and earns no
//! compression claim. The feature-gated `crate::risc0` module is deliberately
//! separate: it proves and verifies real composite or succinct RISC Zero
//! receipts with additional certificate and chain/domain/profile bindings.
//! Neither backend supplies the independent dual-verifier campaign required
//! by M-RECURSIVE-VERIFIER. A receipt that fails verification is worthless
//! everywhere downstream: no proofpower-style credit may ever attach to it.

use core::fmt;
use std::collections::BTreeMap;

use crate::rv32::{execute, Rv32Exit, Rv32Image, Rv32Trap};

const CTX_INPUT: &[u8] = b"noosphere.jet.rv32.input.v1";
const CTX_JOURNAL: &[u8] = b"noosphere.jet.rv32.journal.v1";

/// Receipt wire-format version for [`LocalReceipt`].
pub const LOCAL_RECEIPT_VERSION: u32 = 1;

/// The ABI journal of a halted image: `(status, value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    pub status: u32,
    pub value: u32,
}

impl Journal {
    #[must_use]
    pub fn from_exit(exit: &Rv32Exit) -> Journal {
        Journal {
            status: exit.status,
            value: exit.value,
        }
    }

    /// Canonical 8-byte serialization.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.status.to_le_bytes());
        out[4..].copy_from_slice(&self.value.to_le_bytes());
        out
    }

    /// BLAKE3 journal commitment.
    #[must_use]
    pub fn commit(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(CTX_JOURNAL);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }
}

/// BLAKE3 commitment over the exact input leaves.
#[must_use]
pub fn input_commit(leaves: &[u32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CTX_INPUT);
    h.update(
        &u32::try_from(leaves.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for leaf in leaves {
        h.update(&leaf.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// What must be proven: this exact image, on this exact input, produced
/// this exact journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofRequest {
    pub image_id: [u8; 32],
    pub input_commit: [u8; 32],
    pub journal_commit: [u8; 32],
}

/// Typed rejection. Every variant is a hard reject; the zero-false-accept
/// contract allows false REJECTS only (liveness, never soundness).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// The receipt bytes do not parse as the versioned wire format.
    MalformedReceipt,
    /// The receipt names an image this checker has not pinned.
    UnknownImage,
    /// Receipt image id differs from the request's.
    ImageIdMismatch,
    /// Receipt input does not match the request's input commitment.
    InputMismatch,
    /// Re-execution (or the receipt itself) contradicts the journal
    /// commitment.
    JournalMismatch,
    /// Re-execution trapped; nothing can be verified.
    ExecutionTrap(Rv32Trap),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::MalformedReceipt => f.write_str("malformed receipt"),
            ProofError::UnknownImage => f.write_str("unknown image id"),
            ProofError::ImageIdMismatch => f.write_str("receipt/request image id mismatch"),
            ProofError::InputMismatch => f.write_str("receipt/request input mismatch"),
            ProofError::JournalMismatch => f.write_str("journal mismatch"),
            ProofError::ExecutionTrap(t) => write!(f, "re-execution trapped: {t}"),
        }
    }
}

impl std::error::Error for ProofError {}

/// Receipt verification, independent of the proving backend. `Err` means
/// the receipt earns nothing.
pub trait ReceiptVerifier {
    fn verify(&self, request: &ProofRequest, receipt: &[u8]) -> Result<(), ProofError>;
}

/// The local (non-succinct) receipt: the full input plus the claimed
/// journal. Wire format, all little-endian:
/// `version:u32 || image_id:[32] || leaf_count:u32 || leaves:u32* ||
///  status:u32 || value:u32`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalReceipt {
    pub image_id: [u8; 32],
    pub leaves: Vec<u32>,
    pub journal: Journal,
}

impl LocalReceipt {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LOCAL_RECEIPT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.image_id);
        out.extend_from_slice(
            &u32::try_from(self.leaves.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for leaf in &self.leaves {
            out.extend_from_slice(&leaf.to_le_bytes());
        }
        out.extend_from_slice(&self.journal.canonical_bytes());
        out
    }

    /// Strict decode: exact length, exact version, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<LocalReceipt, ProofError> {
        let mut r = Reader { bytes, pos: 0 };
        if r.u32()? != LOCAL_RECEIPT_VERSION {
            return Err(ProofError::MalformedReceipt);
        }
        let image_id = r.array32()?;
        let count = r.u32()?;
        // Receipts are for lowered images: at most MAX_LEAVES leaves.
        if count == 0 || count > crate::rv32::MAX_LEAVES {
            return Err(ProofError::MalformedReceipt);
        }
        let mut leaves = Vec::with_capacity(count as usize);
        for _ in 0..count {
            leaves.push(r.u32()?);
        }
        let journal = Journal {
            status: r.u32()?,
            value: r.u32()?,
        };
        if r.pos != bytes.len() {
            return Err(ProofError::MalformedReceipt);
        }
        Ok(LocalReceipt {
            image_id,
            leaves,
            journal,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], ProofError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ProofError::MalformedReceipt)?;
        let s = self
            .bytes
            .get(self.pos..end)
            .ok_or(ProofError::MalformedReceipt)?;
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, ProofError> {
        let s = self.take(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(s);
        Ok(u32::from_le_bytes(buf))
    }

    fn array32(&mut self) -> Result<[u8; 32], ProofError> {
        let s = self.take(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(s);
        Ok(buf)
    }
}

/// Deterministic local checker: pinned images, exact re-execution.
pub struct LocalExecutionChecker {
    images: BTreeMap<[u8; 32], Rv32Image>,
    max_steps: u64,
}

impl LocalExecutionChecker {
    #[must_use]
    pub fn new(max_steps: u64) -> LocalExecutionChecker {
        LocalExecutionChecker {
            images: BTreeMap::new(),
            max_steps,
        }
    }

    /// Pin an image; the key is its recomputed id, so a receipt can only
    /// ever name an image by its true hash.
    pub fn register_image(&mut self, image: Rv32Image) -> [u8; 32] {
        let id = image.image_id();
        self.images.insert(id, image);
        id
    }
}

impl ReceiptVerifier for LocalExecutionChecker {
    fn verify(&self, request: &ProofRequest, receipt: &[u8]) -> Result<(), ProofError> {
        let receipt = LocalReceipt::decode(receipt)?;
        if receipt.image_id != request.image_id {
            return Err(ProofError::ImageIdMismatch);
        }
        if input_commit(&receipt.leaves) != request.input_commit {
            return Err(ProofError::InputMismatch);
        }
        let image = self
            .images
            .get(&receipt.image_id)
            .ok_or(ProofError::UnknownImage)?;
        let exit =
            execute(image, &receipt.leaves, self.max_steps).map_err(ProofError::ExecutionTrap)?;
        let journal = Journal::from_exit(&exit);
        if journal != receipt.journal || journal.commit() != request.journal_commit {
            return Err(ProofError::JournalMismatch);
        }
        Ok(())
    }
}

/// Honest local prover: executes `image` and produces the matching
/// `(request, receipt-bytes)` pair.
pub fn prove_local(
    image: &Rv32Image,
    leaves: &[u32],
    max_steps: u64,
) -> Result<(ProofRequest, Vec<u8>), ProofError> {
    let exit = execute(image, leaves, max_steps).map_err(ProofError::ExecutionTrap)?;
    let journal = Journal::from_exit(&exit);
    let receipt = LocalReceipt {
        image_id: image.image_id(),
        leaves: leaves.to_vec(),
        journal,
    };
    let request = ProofRequest {
        image_id: receipt.image_id,
        input_commit: input_commit(leaves),
        journal_commit: journal.commit(),
    };
    Ok((request, receipt.encode()))
}
