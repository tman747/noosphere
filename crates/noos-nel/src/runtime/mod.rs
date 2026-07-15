//! Bounded, allocation-conscious model intake and runtime identity.
//!
//! This module inspects immutable GGUF bytes before a runtime is allowed to
//! allocate model tensors. Model execution remains outside consensus.

pub mod conformance;
pub mod gguf;
pub mod identity;
pub mod profile;

pub use conformance::{inspect_bonsai, BonsaiConformance};
pub use gguf::{
    inspect_gguf, inspect_gguf_path, stream_verify, GgufError, GgufInspection, GgufLimits,
    MetadataSummary, TensorInfo, VerifiedStream,
};
pub use identity::{
    PrismBuildIdentityV2, RuntimeIdentityError, BONSAI_Q1_BYTE_LENGTH, BONSAI_Q1_SHA256,
    PRISM_LLAMA_CPP_COMMIT,
};
pub use profile::{BonsaiExecutionProfileV2, BONSAI_EXECUTION_PROFILE};
