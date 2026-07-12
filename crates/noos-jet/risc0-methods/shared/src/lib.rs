#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};

pub const PROOF_INPUT_VERSION: u32 = 1;
pub const PROOF_CLAIM_VERSION: u32 = 2;
pub const RV32_ABI_VERSION: u32 = 1;
pub const SUBJECT_BASE: u32 = 0x0001_0000;
pub const STACK_TOP: u32 = 0x0002_0000;
pub const MAX_LEAVES: u32 = 24;
pub const MAX_IMAGE_WORDS: u32 = 16_384;
pub const MAX_STEPS: u64 = 1_000_000;

const INPUT_MAGIC: &[u8; 8] = b"NOOSR0I1";
const CLAIM_MAGIC: &[u8; 8] = b"NOOSR0J2";
const CTX_IMAGE: &[u8] = b"noosphere.jet.rv32.image.v1";
const CTX_INPUT: &[u8] = b"noosphere.jet.rv32.input.v1";
const CTX_JOURNAL: &[u8] = b"noosphere.jet.rv32.journal.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MalformedInput,
    UnsupportedVersion,
    InputTooLarge,
    InputArity,
    ImageIdMismatch,
    IllegalInstruction,
    MisalignedAccess,
    AccessOutOfRange,
    PcOutOfRange,
    StepBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofContext {
    pub chain_id: [u8; 32],
    pub domain: [u8; 32],
    pub profile_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofInput {
    pub context: ProofContext,
    pub jet_id: [u8; 32],
    pub semantics_hash: [u8; 32],
    pub cert_digest: [u8; 32],
    pub rv32_image_id: [u8; 32],
    pub leaf_count: u32,
    pub words: Vec<u32>,
    pub leaves: Vec<u32>,
    pub max_steps: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofClaim {
    pub context: ProofContext,
    pub jet_id: [u8; 32],
    pub semantics_hash: [u8; 32],
    pub cert_digest: [u8; 32],
    pub rv32_image_id: [u8; 32],
    pub leaf_count: u32,
    pub input_commit: [u8; 32],
    pub journal_commit: [u8; 32],
    pub status: u32,
    pub value: u32,
    pub steps: u64,
}

impl ProofInput {
    pub fn validate(&self) -> Result<(), Error> {
        if self.leaf_count == 0 || self.leaf_count > MAX_LEAVES {
            return Err(Error::InputArity);
        }
        if usize::try_from(self.leaf_count).ok() != Some(self.leaves.len()) {
            return Err(Error::InputArity);
        }
        if self.words.is_empty()
            || u32::try_from(self.words.len()).unwrap_or(u32::MAX) > MAX_IMAGE_WORDS
        {
            return Err(Error::InputTooLarge);
        }
        if self.max_steps == 0 || self.max_steps > MAX_STEPS {
            return Err(Error::InputTooLarge);
        }
        if image_id(self.leaf_count, &self.words) != self.rv32_image_id {
            return Err(Error::ImageIdMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(INPUT_MAGIC);
        put_u32(&mut out, PROOF_INPUT_VERSION);
        put_context(&mut out, &self.context);
        out.extend_from_slice(&self.jet_id);
        out.extend_from_slice(&self.semantics_hash);
        out.extend_from_slice(&self.cert_digest);
        out.extend_from_slice(&self.rv32_image_id);
        put_u32(&mut out, self.leaf_count);
        put_u32(
            &mut out,
            u32::try_from(self.words.len()).unwrap_or(u32::MAX),
        );
        put_u32(
            &mut out,
            u32::try_from(self.leaves.len()).unwrap_or(u32::MAX),
        );
        put_u64(&mut out, self.max_steps);
        for word in &self.words {
            put_u32(&mut out, *word);
        }
        for leaf in &self.leaves {
            put_u32(&mut out, *leaf);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes, pos: 0 };
        if r.take(8)? != INPUT_MAGIC {
            return Err(Error::MalformedInput);
        }
        if r.u32()? != PROOF_INPUT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let context = ProofContext {
            chain_id: r.array32()?,
            domain: r.array32()?,
            profile_id: r.array32()?,
        };
        let jet_id = r.array32()?;
        let semantics_hash = r.array32()?;
        let cert_digest = r.array32()?;
        let rv32_image_id = r.array32()?;
        let leaf_count = r.u32()?;
        let word_count = r.u32()?;
        let input_count = r.u32()?;
        let max_steps = r.u64()?;
        if word_count == 0 || word_count > MAX_IMAGE_WORDS || input_count > MAX_LEAVES {
            return Err(Error::InputTooLarge);
        }
        let mut words = Vec::with_capacity(word_count as usize);
        for _ in 0..word_count {
            words.push(r.u32()?);
        }
        let mut leaves = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            leaves.push(r.u32()?);
        }
        if r.pos != bytes.len() {
            return Err(Error::MalformedInput);
        }
        let input = Self {
            context,
            jet_id,
            semantics_hash,
            cert_digest,
            rv32_image_id,
            leaf_count,
            words,
            leaves,
            max_steps,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn execute(&self) -> Result<ProofClaim, Error> {
        self.validate()?;
        let exit = execute_rv32(self.leaf_count, &self.words, &self.leaves, self.max_steps)?;
        let journal_commit = journal_commit(exit.status, exit.value);
        Ok(ProofClaim {
            context: self.context,
            jet_id: self.jet_id,
            semantics_hash: self.semantics_hash,
            cert_digest: self.cert_digest,
            rv32_image_id: self.rv32_image_id,
            leaf_count: self.leaf_count,
            input_commit: input_commit(&self.leaves),
            journal_commit,
            status: exit.status,
            value: exit.value,
            steps: exit.steps,
        })
    }
}

impl ProofClaim {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CLAIM_MAGIC);
        put_u32(&mut out, PROOF_CLAIM_VERSION);
        put_context(&mut out, &self.context);
        out.extend_from_slice(&self.jet_id);
        out.extend_from_slice(&self.semantics_hash);
        out.extend_from_slice(&self.cert_digest);
        out.extend_from_slice(&self.rv32_image_id);
        put_u32(&mut out, self.leaf_count);
        out.extend_from_slice(&self.input_commit);
        out.extend_from_slice(&self.journal_commit);
        put_u32(&mut out, self.status);
        put_u32(&mut out, self.value);
        put_u64(&mut out, self.steps);
        out
    }
}

#[must_use]
pub fn image_id(leaf_count: u32, words: &[u32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CTX_IMAGE);
    h.update(&RV32_ABI_VERSION.to_le_bytes());
    h.update(&leaf_count.to_le_bytes());
    h.update(&u32::try_from(words.len()).unwrap_or(u32::MAX).to_le_bytes());
    for word in words {
        h.update(&word.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

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

#[must_use]
pub fn journal_commit(status: u32, value: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CTX_JOURNAL);
    h.update(&status.to_le_bytes());
    h.update(&value.to_le_bytes());
    *h.finalize().as_bytes()
}

#[derive(Clone, Copy)]
struct Exit {
    status: u32,
    value: u32,
    steps: u64,
}

#[allow(clippy::arithmetic_side_effects)]
fn execute_rv32(
    leaf_count: u32,
    words: &[u32],
    leaves: &[u32],
    max_steps: u64,
) -> Result<Exit, Error> {
    if usize::try_from(leaf_count).ok() != Some(leaves.len()) {
        return Err(Error::InputArity);
    }
    let mut regs = [0u32; 32];
    let mut data = BTreeMap::new();
    for (i, leaf) in leaves.iter().enumerate() {
        data.insert(SUBJECT_BASE + 4 * (i as u32), *leaf);
    }
    let mut pc = 0u32;
    let mut steps = 0u64;
    loop {
        steps = steps.saturating_add(1);
        if steps > max_steps {
            return Err(Error::StepBound);
        }
        if !pc.is_multiple_of(4) {
            return Err(Error::PcOutOfRange);
        }
        let word = *words.get((pc / 4) as usize).ok_or(Error::PcOutOfRange)?;
        let opcode = word & 0x7f;
        let rd = (word >> 7) & 0x1f;
        let funct3 = (word >> 12) & 7;
        let rs1 = (word >> 15) & 0x1f;
        let rs2 = (word >> 20) & 0x1f;
        let funct7 = word >> 25;
        let imm_i = ((word as i32) >> 20) as u32;
        let v1 = regs[rs1 as usize];
        let v2 = regs[rs2 as usize];
        let mut next_pc = pc.wrapping_add(4);
        let mut write = None;
        match opcode {
            0x37 => write = Some((rd, word & 0xffff_f000)),
            0x13 if funct3 == 0 => write = Some((rd, v1.wrapping_add(imm_i))),
            0x33 => {
                let value = match (funct3, funct7) {
                    (0, 0x00) => v1.wrapping_add(v2),
                    (0, 0x20) => v1.wrapping_sub(v2),
                    (4, 0x00) => v1 ^ v2,
                    (6, 0x00) => v1 | v2,
                    (7, 0x00) => v1 & v2,
                    (3, 0x00) => u32::from(v1 < v2),
                    _ => return Err(Error::IllegalInstruction),
                };
                write = Some((rd, value));
            }
            0x03 if funct3 == 2 => {
                let addr = v1.wrapping_add(imm_i);
                write = Some((rd, load(&data, addr)?));
            }
            0x23 if funct3 == 2 => {
                let imm_s = ((((word >> 25) << 5) | ((word >> 7) & 0x1f)) as i32)
                    .wrapping_shl(20)
                    .wrapping_shr(20) as u32;
                let addr = v1.wrapping_add(imm_s);
                check_addr(addr)?;
                data.insert(addr, v2);
            }
            0x63 => {
                let imm = ((((word >> 31) & 1) << 12)
                    | (((word >> 7) & 1) << 11)
                    | (((word >> 25) & 0x3f) << 5)
                    | (((word >> 8) & 0xf) << 1)) as i32;
                let imm = (imm << 19) >> 19;
                let take = match funct3 {
                    0 => v1 == v2,
                    1 => v1 != v2,
                    _ => return Err(Error::IllegalInstruction),
                };
                if take {
                    next_pc = pc.wrapping_add(imm as u32);
                }
            }
            0x6f => {
                let imm = ((((word >> 31) & 1) << 20)
                    | (((word >> 12) & 0xff) << 12)
                    | (((word >> 20) & 1) << 11)
                    | (((word >> 21) & 0x3ff) << 1)) as i32;
                let imm = (imm << 11) >> 11;
                write = Some((rd, pc.wrapping_add(4)));
                next_pc = pc.wrapping_add(imm as u32);
            }
            0x73 if word == 0x0000_0073 => {
                return Ok(Exit {
                    status: regs[11],
                    value: regs[10],
                    steps,
                });
            }
            _ => return Err(Error::IllegalInstruction),
        }
        if let Some((register, value)) = write {
            if register != 0 {
                regs[register as usize] = value;
            }
        }
        pc = next_pc;
    }
}

fn check_addr(addr: u32) -> Result<(), Error> {
    if !addr.is_multiple_of(4) {
        return Err(Error::MisalignedAccess);
    }
    if !(SUBJECT_BASE..STACK_TOP).contains(&addr) {
        return Err(Error::AccessOutOfRange);
    }
    Ok(())
}

fn load(data: &BTreeMap<u32, u32>, addr: u32) -> Result<u32, Error> {
    check_addr(addr)?;
    Ok(data.get(&addr).copied().unwrap_or(0))
}

fn put_context(out: &mut Vec<u8>, context: &ProofContext) {
    out.extend_from_slice(&context.chain_id);
    out.extend_from_slice(&context.domain);
    out.extend_from_slice(&context.profile_id);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::MalformedInput)?;
        let value = self.bytes.get(self.pos..end).ok_or(Error::MalformedInput)?;
        self.pos = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn array32(&mut self) -> Result<[u8; 32], Error> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.take(32)?);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn input_round_trip_is_strict() {
        let words = vec![0x0000_0073];
        let input = ProofInput {
            context: ProofContext {
                chain_id: [1; 32],
                domain: [2; 32],
                profile_id: [3; 32],
            },
            jet_id: [4; 32],
            semantics_hash: [5; 32],
            cert_digest: [6; 32],
            rv32_image_id: image_id(1, &words),
            leaf_count: 1,
            words,
            leaves: vec![7],
            max_steps: 10,
        };
        let bytes = input.encode();
        assert_eq!(ProofInput::decode(&bytes), Ok(input));
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(ProofInput::decode(&trailing), Err(Error::MalformedInput));
    }

    #[test]
    fn claim_v2_canonically_binds_leaf_count() {
        let claim = ProofClaim {
            context: ProofContext {
                chain_id: [1; 32],
                domain: [2; 32],
                profile_id: [3; 32],
            },
            jet_id: [4; 32],
            semantics_hash: [5; 32],
            cert_digest: [6; 32],
            rv32_image_id: [7; 32],
            leaf_count: 1,
            input_commit: [8; 32],
            journal_commit: [9; 32],
            status: 10,
            value: 11,
            steps: 12,
        };
        let bytes = claim.canonical_bytes();
        assert_eq!(&bytes[..8], CLAIM_MAGIC);
        assert_eq!(&bytes[8..12], &PROOF_CLAIM_VERSION.to_le_bytes());
        assert_eq!(&bytes[236..240], &claim.leaf_count.to_le_bytes());

        let mut other_arity = claim;
        other_arity.leaf_count = 2;
        assert_ne!(bytes, other_arity.canonical_bytes());
    }
}
