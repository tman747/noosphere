//! Real RISC Zero CPU proving for certified Grain-to-RV32 lowerings.
//!
//! This backend is available only with the `risc0` feature. It compiles and
//! executes an actual RISC Zero guest and produces a cryptographic receipt.
//! [`crate::proof::LocalExecutionChecker`] remains a separate deterministic
//! re-execution backend and is never presented as a RISC Zero proof.

use core::fmt;

use noos_grain::decode_formula;
use noos_jet_risc0_methods::{JET_PROOF_ELF, JET_PROOF_ID};
use noos_jet_risc0_shared::{ProofClaim, ProofContext, ProofInput, MAX_STEPS as RISC0_MAX_STEPS};
use risc0_zkvm::{ExecutorEnv, LocalProver, Prover, ProverOpts, Receipt, VerifierContext};

use crate::cert::JetId;
use crate::proof::{input_commit, Journal};
use crate::registry::JetRegistry;
use crate::rv32::{execute, lower, Rv32Image, Rv32Trap};

pub type Risc0ProofContext = ProofContext;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Risc0ProofInput {
    input: ProofInput,
    request: Risc0ProofRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Risc0ProofRequest {
    pub method_id: [u32; 8],
    pub claim: ProofClaim,
}

#[derive(Clone)]
pub struct Risc0Receipt {
    receipt: Receipt,
}

impl Risc0Receipt {
    #[must_use]
    pub fn journal_bytes(&self) -> &[u8] {
        &self.receipt.journal.bytes
    }

    #[must_use]
    pub fn is_succinct(&self) -> bool {
        self.receipt.inner.succinct().is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Risc0Error {
    UncertifiedJet,
    MalformedCertifiedFormula,
    ImageSubstitution,
    InputArity,
    InvalidProofInput(noos_jet_risc0_shared::Error),
    HostExecution(Rv32Trap),
    Proving(String),
    MethodImageMismatch,
    ContextMismatch,
    CertificateMismatch,
    ReceiptVerification,
    JournalMismatch,
}

impl fmt::Display for Risc0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Risc0Error::UncertifiedJet => f.write_str("jet is not admitted"),
            Risc0Error::MalformedCertifiedFormula => {
                f.write_str("admitted certificate formula is malformed")
            }
            Risc0Error::ImageSubstitution => {
                f.write_str("RV32 image is not the canonical certified lowering")
            }
            Risc0Error::InputArity => f.write_str("RV32 input arity mismatch"),
            Risc0Error::InvalidProofInput(error) => write!(f, "invalid proof input: {error:?}"),
            Risc0Error::HostExecution(trap) => write!(f, "host RV32 execution trapped: {trap}"),
            Risc0Error::Proving(error) => write!(f, "RISC Zero proving failed: {error}"),
            Risc0Error::MethodImageMismatch => f.write_str("RISC Zero method image mismatch"),
            Risc0Error::ContextMismatch => f.write_str("chain/domain/profile mismatch"),
            Risc0Error::CertificateMismatch => f.write_str("certificate binding mismatch"),
            Risc0Error::ReceiptVerification => f.write_str("RISC Zero receipt verification failed"),
            Risc0Error::JournalMismatch => f.write_str("RISC Zero journal/claim mismatch"),
        }
    }
}

impl std::error::Error for Risc0Error {}

impl Risc0ProofInput {
    pub fn certified(
        registry: &JetRegistry,
        jet_id: &JetId,
        image: &Rv32Image,
        leaves: &[u32],
        context: Risc0ProofContext,
        max_steps: u64,
    ) -> Result<Self, Risc0Error> {
        let cert = registry.cert(jet_id).ok_or(Risc0Error::UncertifiedJet)?;
        let formula =
            decode_formula(&cert.formula).map_err(|_| Risc0Error::MalformedCertifiedFormula)?;
        let expected =
            lower(&formula, image.leaf_count).map_err(|_| Risc0Error::ImageSubstitution)?;
        if expected != *image {
            return Err(Risc0Error::ImageSubstitution);
        }
        if usize::try_from(image.leaf_count).ok() != Some(leaves.len()) {
            return Err(Risc0Error::InputArity);
        }
        if max_steps == 0 || max_steps > RISC0_MAX_STEPS {
            return Err(Risc0Error::InvalidProofInput(
                noos_jet_risc0_shared::Error::InputTooLarge,
            ));
        }
        let exit = execute(image, leaves, max_steps).map_err(Risc0Error::HostExecution)?;
        let journal = Journal::from_exit(&exit);
        let claim = ProofClaim {
            context,
            jet_id: cert.jet_id.0,
            semantics_hash: cert.semantics_hash.0,
            cert_digest: cert.digest,
            rv32_image_id: image.image_id(),
            input_commit: input_commit(leaves),
            journal_commit: journal.commit(),
            status: exit.status,
            value: exit.value,
            steps: exit.steps,
        };
        let input = ProofInput {
            context,
            jet_id: cert.jet_id.0,
            semantics_hash: cert.semantics_hash.0,
            cert_digest: cert.digest,
            rv32_image_id: image.image_id(),
            leaf_count: image.leaf_count,
            words: image.words.clone(),
            leaves: leaves.to_vec(),
            max_steps,
        };
        input.validate().map_err(Risc0Error::InvalidProofInput)?;
        Ok(Self {
            input,
            request: Risc0ProofRequest {
                method_id: JET_PROOF_ID,
                claim,
            },
        })
    }

    #[must_use]
    pub fn request(&self) -> &Risc0ProofRequest {
        &self.request
    }

    #[must_use]
    pub fn canonical_guest_input(&self) -> Vec<u8> {
        self.input.encode()
    }
}

pub fn prove_risc0_cpu(
    input: &Risc0ProofInput,
) -> Result<(Risc0ProofRequest, Risc0Receipt), Risc0Error> {
    prove_with_options(input, ProverOpts::composite().with_dev_mode(false))
}

/// Produce a recursively compressed RISC Zero receipt on the local CPU. This
/// is a RISC Zero recursion precursor only; it is not the independently
/// reproduced Pearl Plonky2/STARKy path named by M-RECURSIVE-VERIFIER.
pub fn prove_risc0_succinct_cpu(
    input: &Risc0ProofInput,
) -> Result<(Risc0ProofRequest, Risc0Receipt), Risc0Error> {
    prove_with_options(input, ProverOpts::succinct().with_dev_mode(false))
}

fn prove_with_options(
    input: &Risc0ProofInput,
    options: ProverOpts,
) -> Result<(Risc0ProofRequest, Risc0Receipt), Risc0Error> {
    let bytes = input.input.encode();
    let byte_len = u32::try_from(bytes.len())
        .map_err(|_| Risc0Error::InvalidProofInput(noos_jet_risc0_shared::Error::InputTooLarge))?;
    let env = ExecutorEnv::builder()
        .write_slice(&[byte_len])
        .write_slice(&bytes)
        .build()
        .map_err(|error| Risc0Error::Proving(error.to_string()))?;
    let prove_info = LocalProver::new("noosphere-risc0-cpu")
        .prove_with_opts(env, JET_PROOF_ELF, &options)
        .map_err(|error| Risc0Error::Proving(error.to_string()))?;
    Ok((
        input.request.clone(),
        Risc0Receipt {
            receipt: prove_info.receipt,
        },
    ))
}

pub struct Risc0Verifier<'a> {
    registry: &'a JetRegistry,
    context: Risc0ProofContext,
}

impl<'a> Risc0Verifier<'a> {
    #[must_use]
    pub fn new(registry: &'a JetRegistry, context: Risc0ProofContext) -> Self {
        Self { registry, context }
    }

    pub fn verify(
        &self,
        request: &Risc0ProofRequest,
        receipt: &Risc0Receipt,
    ) -> Result<(), Risc0Error> {
        if request.method_id != JET_PROOF_ID {
            return Err(Risc0Error::MethodImageMismatch);
        }
        if request.claim.context != self.context {
            return Err(Risc0Error::ContextMismatch);
        }
        let jet_id = JetId(request.claim.jet_id);
        let cert = self
            .registry
            .cert(&jet_id)
            .ok_or(Risc0Error::UncertifiedJet)?;
        if cert.semantics_hash.0 != request.claim.semantics_hash
            || cert.digest != request.claim.cert_digest
        {
            return Err(Risc0Error::CertificateMismatch);
        }
        let verifier_context = VerifierContext::default().with_dev_mode(false);
        receipt
            .receipt
            .verify_with_context(&verifier_context, JET_PROOF_ID)
            .map_err(|_| Risc0Error::ReceiptVerification)?;
        if receipt.receipt.journal.bytes != request.claim.canonical_bytes() {
            return Err(Risc0Error::JournalMismatch);
        }
        Ok(())
    }
}

#[must_use]
pub const fn risc0_method_id() -> [u32; 8] {
    JET_PROOF_ID
}

#[cfg(test)]
pub(crate) fn tamper_receipt_journal(receipt: &mut Risc0Receipt) {
    if let Some(first) = receipt.receipt.journal.bytes.first_mut() {
        *first ^= 1;
    }
}
