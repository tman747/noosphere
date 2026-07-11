#![forbid(unsafe_code)]

/// RISC Zero 3.0.5 combined user/kernel method binary, reproducibly built by
/// `rebuild-guest.ps1` with `risc0-guest-builder:r0.1.88.0`.
pub const JET_PROOF_ELF: &[u8] = include_bytes!("../artifacts/jet_proof.bin");

/// Image ID emitted by `risc0-build` for [`JET_PROOF_ELF`]. Verification also
/// recomputes this binding inside the RISC Zero receipt verifier.
pub const JET_PROOF_ID: [u32; 8] = [
    153_104_521,
    790_661_893,
    521_854_043,
    2_062_665_801,
    2_652_890_336,
    2_819_343_462,
    2_116_612_749,
    1_963_227_728,
];
