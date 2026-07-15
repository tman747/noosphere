use blake3::Hasher;
use std::fmt;

pub const BONSAI_Q1_BYTE_LENGTH: u64 = 3_803_452_480;
pub const BONSAI_Q1_SHA256: [u8; 32] = [
    0x17, 0xef, 0x84, 0x2e, 0x47, 0x45, 0x0c, 0xae, 0xb8, 0xea, 0xa3, 0xeb, 0xfb, 0xba, 0xb5, 0xd2,
    0xf2, 0x27, 0x8b, 0x62, 0xb7, 0x9b, 0xe1, 0x07, 0x98, 0x5f, 0xb6, 0x9a, 0x2f, 0x81, 0x9a, 0xa0,
];
pub const PRISM_LLAMA_CPP_COMMIT: &str = "62061f91088281e65071cc38c5f69ee95c39f14e";
const BUILD_ID_DOMAIN: &[u8] = b"NOOS/WWM/PRISM-BUILD/V2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrismBuildIdentityV2 {
    pub source_commit: String,
    pub target_triple: String,
    pub toolchain: String,
    pub build_flags: Vec<String>,
    pub binary_sha256: [u8; 32],
    pub sbom_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeIdentityError {
    UnpinnedSource,
    EmptyField,
    InvalidBuildFlags,
    MissingDigest,
}

impl fmt::Display for RuntimeIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RuntimeIdentityError {}

impl PrismBuildIdentityV2 {
    pub fn validate(&self) -> Result<(), RuntimeIdentityError> {
        if self.source_commit != PRISM_LLAMA_CPP_COMMIT {
            return Err(RuntimeIdentityError::UnpinnedSource);
        }
        if self.target_triple.is_empty() || self.toolchain.is_empty() {
            return Err(RuntimeIdentityError::EmptyField);
        }
        if self.binary_sha256 == [0; 32] || self.sbom_root == [0; 32] {
            return Err(RuntimeIdentityError::MissingDigest);
        }
        if self.build_flags.len() > 128
            || self
                .build_flags
                .iter()
                .any(|flag| flag.is_empty() || flag.len() > 512)
            || !self.build_flags.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(RuntimeIdentityError::InvalidBuildFlags);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimeIdentityError> {
        self.validate()?;
        let mut bytes = Vec::new();
        put_bytes(&mut bytes, BUILD_ID_DOMAIN);
        put_bytes(&mut bytes, self.source_commit.as_bytes());
        put_bytes(&mut bytes, self.target_triple.as_bytes());
        put_bytes(&mut bytes, self.toolchain.as_bytes());
        put_u32(
            &mut bytes,
            u32::try_from(self.build_flags.len())
                .map_err(|_| RuntimeIdentityError::InvalidBuildFlags)?,
        );
        for flag in &self.build_flags {
            put_bytes(&mut bytes, flag.as_bytes());
        }
        bytes.extend_from_slice(&self.binary_sha256);
        bytes.extend_from_slice(&self.sbom_root);
        Ok(bytes)
    }

    pub fn build_id(&self) -> Result<[u8; 32], RuntimeIdentityError> {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes()?);
        Ok(*hasher.finalize().as_bytes())
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    put_u32(bytes, u32::try_from(value.len()).unwrap_or(u32::MAX));
    bytes.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build() -> PrismBuildIdentityV2 {
        PrismBuildIdentityV2 {
            source_commit: PRISM_LLAMA_CPP_COMMIT.into(),
            target_triple: "x86_64-pc-windows-msvc".into(),
            toolchain: "msvc-19.44".into(),
            build_flags: vec!["GGML_HIP=ON".into(), "LLAMA_CURL=OFF".into()],
            binary_sha256: [1; 32],
            sbom_root: [2; 32],
        }
    }

    #[test]
    fn exact_model_digest_constant_is_not_abbreviated() {
        assert_eq!(
            crate::runtime::gguf::hex(&BONSAI_Q1_SHA256),
            "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
        );
        assert_eq!(BONSAI_Q1_BYTE_LENGTH, 3_803_452_480);
    }

    #[test]
    fn build_identity_covers_every_field() {
        let value = build();
        let id = value.build_id().unwrap();
        let mut changed = value.clone();
        changed.binary_sha256[0] ^= 1;
        assert_ne!(changed.build_id().unwrap(), id);
        let mut changed = value.clone();
        changed.build_flags[0].push('X');
        assert_ne!(changed.build_id().unwrap(), id);
        let mut changed = value;
        changed.source_commit = "0000000000000000000000000000000000000000".into();
        assert_eq!(
            changed.build_id(),
            Err(RuntimeIdentityError::UnpinnedSource)
        );
    }
}
