use super::gguf::{inspect_gguf_path, GgufError, GgufInspection, GgufLimits};
use super::identity::{BONSAI_Q1_BYTE_LENGTH, BONSAI_Q1_SHA256, PRISM_LLAMA_CPP_COMMIT};
use super::profile::BONSAI_EXECUTION_PROFILE;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BonsaiConformance {
    pub inspection: GgufInspection,
    pub runtime_commit: &'static str,
    pub max_context_tokens: u32,
    pub max_output_tokens: u32,
    pub model_allocation_performed: bool,
}

pub fn inspect_bonsai(path: impl AsRef<Path>) -> Result<BonsaiConformance, GgufError> {
    let inspection = inspect_gguf_path(
        path,
        BONSAI_Q1_BYTE_LENGTH,
        BONSAI_Q1_SHA256,
        GgufLimits::default(),
    )?;
    Ok(BonsaiConformance {
        inspection,
        runtime_commit: PRISM_LLAMA_CPP_COMMIT,
        max_context_tokens: BONSAI_EXECUTION_PROFILE.max_context_tokens,
        max_output_tokens: BONSAI_EXECUTION_PROFILE.max_output_tokens,
        model_allocation_performed: false,
    })
}
