#![forbid(unsafe_code)]

/// RISC Zero 3.0.5 combined user/kernel method binary, reproducibly built by
/// `rebuild-guest.ps1` with `risc0-guest-builder:r0.1.88.0`.
pub const JET_PROOF_ELF: &[u8] = include_bytes!("../artifacts/jet_proof.bin");

/// Image ID emitted by `risc0-build` for [`JET_PROOF_ELF`]. Verification also
/// recomputes this binding inside the RISC Zero receipt verifier.
pub const JET_PROOF_ID: [u32; 8] = [
    3_331_342_360,
    2_812_859_915,
    664_723_635,
    1_096_628_783,
    824_915_127,
    4_136_200_196,
    2_460_030_790,
    292_355_732,
];
