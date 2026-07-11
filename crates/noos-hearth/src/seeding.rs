//! Content-addressed systematic Reed-Solomon 8-of-12 seeding and resumable fetches.
#![allow(clippy::arithmetic_side_effects, clippy::needless_range_loop)]

use crate::domain_hash;
use noos_species::Hash32;
use std::collections::{BTreeMap, BTreeSet};

pub const DATA_SHARDS: usize = 8;
pub const PARITY_SHARDS: usize = 4;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureShard {
    pub artifact_root: Hash32,
    pub index: u8,
    pub original_len: u64,
    pub bytes: Vec<u8>,
    pub bytes_root: Hash32,
}

impl ErasureShard {
    #[must_use]
    pub fn calculate_root(&self) -> Hash32 {
        domain_hash(
            "NOOS/HEARTH/ERASURE-SHARD/V1",
            &[
                &self.artifact_root,
                &[self.index],
                &self.original_len.to_le_bytes(),
                &(self.bytes.len() as u64).to_le_bytes(),
                &self.bytes,
            ],
        )
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        usize::from(self.index) < TOTAL_SHARDS && self.bytes_root == self.calculate_root()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureArtifact {
    pub artifact_root: Hash32,
    pub original_len: u64,
    pub shard_roots: [Hash32; TOTAL_SHARDS],
    pub shards: Vec<ErasureShard>,
}

#[must_use]
pub fn artifact_root(bytes: &[u8]) -> Hash32 {
    domain_hash(
        "NOOS/SPECIES/ARTIFACT/V1",
        &[&(bytes.len() as u64).to_le_bytes(), bytes],
    )
}

pub fn encode_8_of_12(bytes: &[u8]) -> Result<ErasureArtifact, SeedError> {
    let original_len = u64::try_from(bytes.len()).map_err(|_| SeedError::LengthOverflow)?;
    let root = artifact_root(bytes);
    let shard_len = bytes.len().div_ceil(DATA_SHARDS).max(1);
    let mut data = vec![vec![0u8; shard_len]; DATA_SHARDS];
    for (index, byte) in bytes.iter().copied().enumerate() {
        data[index / shard_len][index % shard_len] = byte;
    }
    let generator = systematic_generator()?;
    let mut encoded = vec![vec![0u8; shard_len]; TOTAL_SHARDS];
    for row in 0..TOTAL_SHARDS {
        for col in 0..DATA_SHARDS {
            for position in 0..shard_len {
                encoded[row][position] ^= gf_mul(generator[row][col], data[col][position]);
            }
        }
    }
    let shards = encoded
        .into_iter()
        .enumerate()
        .map(|(index, shard_bytes)| {
            let mut shard = ErasureShard {
                artifact_root: root,
                index: u8::try_from(index).map_err(|_| SeedError::LengthOverflow)?,
                original_len,
                bytes: shard_bytes,
                bytes_root: [0; 32],
            };
            shard.bytes_root = shard.calculate_root();
            Ok(shard)
        })
        .collect::<Result<Vec<_>, SeedError>>()?;
    let shard_roots = std::array::from_fn(|index| shards[index].bytes_root);
    Ok(ErasureArtifact {
        artifact_root: root,
        original_len,
        shard_roots,
        shards,
    })
}

pub fn reconstruct_8_of_12(shards: &[ErasureShard]) -> Result<Vec<u8>, SeedError> {
    if shards.len() < DATA_SHARDS {
        return Err(SeedError::InsufficientShards);
    }
    let selected = &shards[..DATA_SHARDS];
    let root = selected[0].artifact_root;
    let original_len = selected[0].original_len;
    let shard_len = selected[0].bytes.len();
    let mut indices = BTreeSet::new();
    if selected.iter().any(|shard| {
        !shard.verify()
            || shard.artifact_root != root
            || shard.original_len != original_len
            || shard.bytes.len() != shard_len
            || !indices.insert(shard.index)
    }) {
        return Err(SeedError::CorruptShard);
    }
    let generator = systematic_generator()?;
    let decode_matrix = selected
        .iter()
        .map(|shard| generator[usize::from(shard.index)].clone())
        .collect::<Vec<_>>();
    let inverse = invert_matrix(decode_matrix)?;
    let mut data = vec![vec![0u8; shard_len]; DATA_SHARDS];
    for row in 0..DATA_SHARDS {
        for col in 0..DATA_SHARDS {
            for position in 0..shard_len {
                data[row][position] ^= gf_mul(inverse[row][col], selected[col].bytes[position]);
            }
        }
    }
    let mut bytes = data.into_iter().flatten().collect::<Vec<_>>();
    bytes.truncate(usize::try_from(original_len).map_err(|_| SeedError::LengthOverflow)?);
    if artifact_root(&bytes) != root {
        return Err(SeedError::ArtifactRootMismatch);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedFetch {
    pub artifact_root: Hash32,
    pub original_len: u64,
    pub expected_roots: [Hash32; TOTAL_SHARDS],
    accepted: BTreeMap<u8, ErasureShard>,
    departed_seeders: BTreeSet<Hash32>,
    pub corrupt_rejections: u64,
    pub source_changes: u64,
}

impl SeedFetch {
    #[must_use]
    pub fn new(artifact: &ErasureArtifact) -> Self {
        Self {
            artifact_root: artifact.artifact_root,
            original_len: artifact.original_len,
            expected_roots: artifact.shard_roots,
            accepted: BTreeMap::new(),
            departed_seeders: BTreeSet::new(),
            corrupt_rejections: 0,
            source_changes: 0,
        }
    }

    pub fn accept(&mut self, seeder: Hash32, shard: ErasureShard) -> Result<(), SeedError> {
        if self.departed_seeders.contains(&seeder) {
            return Err(SeedError::SeederDeparted);
        }
        let index = usize::from(shard.index);
        if index >= TOTAL_SHARDS
            || shard.artifact_root != self.artifact_root
            || shard.original_len != self.original_len
            || !shard.verify()
            || self.expected_roots[index] != shard.bytes_root
        {
            self.corrupt_rejections = self.corrupt_rejections.saturating_add(1);
            return Err(SeedError::CorruptShard);
        }
        if self.accepted.contains_key(&shard.index) {
            return Err(SeedError::DuplicateShard);
        }
        self.accepted.insert(shard.index, shard);
        Ok(())
    }

    pub fn depart(&mut self, seeder: Hash32) {
        if self.departed_seeders.insert(seeder) {
            self.source_changes = self.source_changes.saturating_add(1);
        }
    }

    #[must_use]
    pub fn ready(&self) -> bool {
        self.accepted.len() >= DATA_SHARDS
    }

    pub fn finish(&self) -> Result<Vec<u8>, SeedError> {
        reconstruct_8_of_12(&self.accepted.values().cloned().collect::<Vec<_>>())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedRaceObservation {
    pub fresh_hearths: u32,
    pub seeders: u8,
    pub median_join_seconds: u64,
    pub modeled_join_seconds: u64,
    pub corrupted_shards_accepted: u64,
    pub recovered_without_restart: bool,
}

impl SeedRaceObservation {
    #[must_use]
    pub fn threshold_met(self) -> bool {
        self.fresh_hearths >= 100
            && matches!(self.seeders, 5 | 10)
            && self.median_join_seconds <= self.modeled_join_seconds.saturating_mul(2)
            && self.corrupted_shards_accepted == 0
            && self.recovered_without_restart
    }
}

fn systematic_generator() -> Result<Vec<Vec<u8>>, SeedError> {
    let vandermonde = (0..TOTAL_SHARDS)
        .map(|row| {
            let x = u8::try_from(row + 1).unwrap_or(1);
            (0..DATA_SHARDS)
                .map(|power| gf_pow(x, u8::try_from(power).unwrap_or(0)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let top_inverse = invert_matrix(vandermonde[..DATA_SHARDS].to_vec())?;
    Ok(matrix_multiply(&vandermonde, &top_inverse))
}

fn matrix_multiply(left: &[Vec<u8>], right: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let rows = left.len();
    let inner = right.len();
    let cols = right[0].len();
    let mut out = vec![vec![0; cols]; rows];
    for row in 0..rows {
        for col in 0..cols {
            for k in 0..inner {
                out[row][col] ^= gf_mul(left[row][k], right[k][col]);
            }
        }
    }
    out
}

fn invert_matrix(mut matrix: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, SeedError> {
    let size = matrix.len();
    if size == 0 || matrix.iter().any(|row| row.len() != size) {
        return Err(SeedError::SingularCodingMatrix);
    }
    let mut inverse = vec![vec![0u8; size]; size];
    for (index, row) in inverse.iter_mut().enumerate() {
        row[index] = 1;
    }
    for col in 0..size {
        let pivot = (col..size)
            .find(|&row| matrix[row][col] != 0)
            .ok_or(SeedError::SingularCodingMatrix)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);
        let scale = gf_inv(matrix[col][col]).ok_or(SeedError::SingularCodingMatrix)?;
        for item in 0..size {
            matrix[col][item] = gf_mul(matrix[col][item], scale);
            inverse[col][item] = gf_mul(inverse[col][item], scale);
        }
        for row in 0..size {
            if row == col || matrix[row][col] == 0 {
                continue;
            }
            let factor = matrix[row][col];
            for item in 0..size {
                matrix[row][item] ^= gf_mul(factor, matrix[col][item]);
                inverse[row][item] ^= gf_mul(factor, inverse[col][item]);
            }
        }
    }
    Ok(inverse)
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    result
}

fn gf_pow(base: u8, exponent: u8) -> u8 {
    (0..exponent).fold(1, |value, _| gf_mul(value, base))
}

fn gf_inv(value: u8) -> Option<u8> {
    (value != 0).then(|| gf_pow(value, 254))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedError {
    LengthOverflow,
    InsufficientShards,
    CorruptShard,
    DuplicateShard,
    ArtifactRootMismatch,
    SeederDeparted,
    SingularCodingMatrix,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    #[test]
    fn every_eight_shard_pattern_reconstructs_exact_bytes() {
        let bytes = (0u8..=250).cycle().take(4_097).collect::<Vec<_>>();
        let artifact = encode_8_of_12(&bytes).unwrap();
        for omitted_a in 0..TOTAL_SHARDS {
            for omitted_b in (omitted_a + 1)..TOTAL_SHARDS {
                for omitted_c in (omitted_b + 1)..TOTAL_SHARDS {
                    for omitted_d in (omitted_c + 1)..TOTAL_SHARDS {
                        let selected = artifact
                            .shards
                            .iter()
                            .enumerate()
                            .filter(|(index, _)| {
                                ![omitted_a, omitted_b, omitted_c, omitted_d].contains(index)
                            })
                            .map(|(_, shard)| shard.clone())
                            .collect::<Vec<_>>();
                        assert_eq!(reconstruct_8_of_12(&selected).unwrap(), bytes);
                    }
                }
            }
        }
    }

    #[test]
    fn corruption_rejects_and_departure_resumes_without_restart() {
        let bytes =
            b"canonical Species member bytes repeated across a residential seeding race".repeat(20);
        let artifact = encode_8_of_12(&bytes).unwrap();
        let mut fetch = SeedFetch::new(&artifact);
        for index in 0..4 {
            fetch.accept(h(1), artifact.shards[index].clone()).unwrap();
        }
        fetch.depart(h(1));
        let mut corrupt = artifact.shards[4].clone();
        corrupt.bytes[0] ^= 1;
        assert_eq!(fetch.accept(h(2), corrupt), Err(SeedError::CorruptShard));
        for index in 4..8 {
            fetch.accept(h(2), artifact.shards[index].clone()).unwrap();
        }
        assert!(fetch.ready());
        assert_eq!(fetch.finish().unwrap(), bytes);
        assert_eq!(fetch.corrupt_rejections, 1);
        assert_eq!(fetch.source_changes, 1);
    }

    #[test]
    fn shard_transplant_between_artifacts_is_rejected() {
        let first = encode_8_of_12(b"first artifact").unwrap();
        let second = encode_8_of_12(b"second artifact").unwrap();
        let mut fetch = SeedFetch::new(&first);
        assert_eq!(
            fetch.accept(h(1), second.shards[0].clone()),
            Err(SeedError::CorruptShard)
        );
    }
}
