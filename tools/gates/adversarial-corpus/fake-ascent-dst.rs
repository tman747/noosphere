// Adversarial sample: old Ascent BLS domain-separation tags and env prefix.
// The scanner must flag every line below.
pub const BLS_SIG_DST: &[u8] = b"ASCENT-BLS-SIG-V1";
pub const BLS_STAGE_ATTEST_DST: &[u8] = b"ASCENT-BLS-STAGE-ATTEST-V0";
const AUTH_ENV: &str = "ASCENT_RPC_AUTH_TOKEN";
