use super::identity::{BONSAI_Q1_SHA256, PRISM_LLAMA_CPP_COMMIT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BonsaiExecutionProfileV2 {
    pub model_sha256: [u8; 32],
    pub runtime_commit: &'static str,
    pub max_context_tokens: u32,
    pub max_output_tokens: u32,
    pub attachments_allowed: bool,
    pub text_only: bool,
}

impl BonsaiExecutionProfileV2 {
    pub const fn validate_request(self, input_tokens: u32, output_tokens: u32) -> bool {
        if output_tokens > self.max_output_tokens {
            return false;
        }
        match input_tokens.checked_add(output_tokens) {
            Some(total) => total <= self.max_context_tokens,
            None => false,
        }
    }
}

pub const BONSAI_EXECUTION_PROFILE: BonsaiExecutionProfileV2 = BonsaiExecutionProfileV2 {
    model_sha256: BONSAI_Q1_SHA256,
    runtime_commit: PRISM_LLAMA_CPP_COMMIT,
    max_context_tokens: 4_096,
    max_output_tokens: 512,
    attachments_allowed: false,
    text_only: true,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_enforces_combined_and_output_bounds() {
        assert!(BONSAI_EXECUTION_PROFILE.validate_request(3_584, 512));
        assert!(!BONSAI_EXECUTION_PROFILE.validate_request(3_585, 512));
        assert!(!BONSAI_EXECUTION_PROFILE.validate_request(1, 513));
        assert!(!BONSAI_EXECUTION_PROFILE.attachments_allowed);
        assert!(BONSAI_EXECUTION_PROFILE.text_only);
    }
}
