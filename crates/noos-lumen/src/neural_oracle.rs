//! Canonical neural-oracle contracts and the bounded L1 trinary evaluator.
//!
//! Large-model execution remains outside consensus and reaches this surface
//! through WWM jobs. The L1 evaluator is intentionally tiny: one fixed-shape
//! trinary hidden layer with exact integer arithmetic and a closed operation
//! bound. Neither path has proposal, issuance, membership, or finality weight.

use crate::{
    domain_hash, domains,
    objects::{BoundedBytes, BoundedList},
    Hash32,
};
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};

pub const MAX_L1_NEURAL_INPUTS: usize = 32;
pub const MAX_L1_NEURAL_HIDDEN: usize = 32;
pub const MAX_L1_NEURAL_OUTPUTS: usize = 32;
pub const MAX_L1_NEURAL_WEIGHTS: u32 = 1_024;
pub const MAX_NEURAL_ORACLE_RESPONSE_BYTES: u32 = 16_384;
pub const MAX_NEURAL_ORACLE_REPORTERS: u32 = 3;
pub const NEURAL_ORACLE_QUORUM_THRESHOLD: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NeuralOracleMode {
    L1Deterministic = 0,
    WwmQuorum = 1,
}

impl NoosEncode for NeuralOracleMode {
    fn encode(&self, writer: &mut Writer) {
        writer.put_u8(*self as u8);
    }
}

impl NoosDecode for NeuralOracleMode {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match reader.get_u8()? {
            0 => Ok(Self::L1Deterministic),
            1 => Ok(Self::WwmQuorum),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NeuralOracleStatus {
    Success = 0,
    NoQuorum = 1,
}

impl NoosEncode for NeuralOracleStatus {
    fn encode(&self, writer: &mut Writer) {
        writer.put_u8(*self as u8);
    }
}

impl NoosDecode for NeuralOracleStatus {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match reader.get_u8()? {
            0 => Ok(Self::Success),
            1 => Ok(Self::NoQuorum),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

define_object! {
    /// Immutable one-hidden-layer trinary program executed by every L1 node.
    /// Trit encoding is closed: `0=-1`, `1=0`, `2=+1`.
    pub struct NeuralProgramV1 {
        version: 1;
        1 => program_id: [u8; 32],
        2 => input_width: u8,
        3 => hidden_width: u8,
        4 => output_width: u8,
        5 => hidden_weights: BoundedBytes<1024>,
        6 => hidden_biases: BoundedBytes<32>,
        7 => output_weights: BoundedBytes<1024>,
        8 => output_biases: BoundedBytes<32>,
    }
}

define_object! {
    /// Direct L1 evaluation request. `query_id` is caller-chosen and replay
    /// protected by the result key; `requester` must sign the transaction.
    pub struct EvaluateNeuralProgramV1 {
        version: 1;
        1 => query_id: [u8; 32],
        2 => program_id: [u8; 32],
        3 => requester: [u8; 32],
        4 => input: BoundedBytes<32>,
    }
}

define_object! {
    /// Qubic-style commit/reveal query bound one-to-one to a canonical WWM job.
    pub struct NeuralOracleQueryV1 {
        version: 1;
        1 => query_id: [u8; 32],
        2 => job_id: [u8; 32],
        3 => requester: [u8; 32],
        4 => executor_set_id: [u8; 32],
        5 => executor_set_epoch: u64,
        6 => input_root: [u8; 32],
        7 => max_response_bytes: u32,
        8 => threshold: u8,
        9 => commit_deadline: u64,
        10 => reveal_deadline: u64,
    }
}

define_object! {
    /// First phase of an executor reply. The transaction must be signed by the
    /// operator account belonging to `reporter_profile_id`.
    pub struct NeuralOracleCommitV1 {
        version: 1;
        1 => query_id: [u8; 32],
        2 => reporter_profile_id: [u8; 32],
        3 => commitment: [u8; 32],
    }
}

define_object! {
    /// Reveal of exact raw model bytes. No median, haircut, TWAP, or semantic
    /// reinterpretation is applied by consensus.
    pub struct NeuralOracleRevealV1 {
        version: 1;
        1 => query_id: [u8; 32],
        2 => reporter_profile_id: [u8; 32],
        3 => response: BoundedBytes<16384>,
        4 => transcript_root: [u8; 32],
        5 => nonce: [u8; 32],
    }
}

define_object! {
    /// Permissionless timeout finalizer. It can only produce `NoQuorum` after
    /// the frozen reveal deadline and cannot replace a successful result.
    pub struct FinalizeNeuralOracleQueryV1 {
        version: 1;
        1 => query_id: [u8; 32],
    }
}

define_object! {
    pub struct NeuralOracleCommitRecordV1 {
        version: 1;
        1 => query_id: [u8; 32],
        2 => reporter_profile_id: [u8; 32],
        3 => commitment: [u8; 32],
        4 => committed_height: u64,
    }
}

define_object! {
    pub struct NeuralOracleRevealRecordV1 {
        version: 1;
        1 => query_id: [u8; 32],
        2 => reporter_profile_id: [u8; 32],
        3 => response: BoundedBytes<16384>,
        4 => output_root: [u8; 32],
        5 => transcript_root: [u8; 32],
        6 => revealed_height: u64,
    }
}

define_object! {
    /// Final raw result. `source_id` is a NeuralProgram ID in L1 mode and a
    /// ModelCapsule ID in WWM mode. Empty signer lists are legal only in L1
    /// mode, where ordinary block replay supplies agreement.
    pub struct NeuralOracleResultV1 {
        version: 1;
        1 => result_id: [u8; 32],
        2 => query_id: [u8; 32],
        3 => mode: NeuralOracleMode,
        4 => status: NeuralOracleStatus,
        5 => source_id: [u8; 32],
        6 => execution_profile_id: [u8; 32],
        7 => input_root: [u8; 32],
        8 => response: BoundedBytes<16384>,
        9 => output_root: [u8; 32],
        10 => transcript_root: [u8; 32],
        11 => signer_profile_ids: BoundedList<[u8;32],3>,
        12 => finalized_height: u64,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeuralProgramError {
    InvalidIdentity,
    InvalidShape,
    InvalidTrit,
    InvalidBias,
    InvalidInput,
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeuralEvaluation {
    pub output: BoundedBytes<32>,
    pub operations: u64,
}

#[must_use]
pub fn neural_program_id(program: &NeuralProgramV1) -> Hash32 {
    domain_hash(
        domains::NEURAL_ORACLE_PROGRAM,
        &[
            &[
                program.input_width,
                program.hidden_width,
                program.output_width,
            ],
            program.hidden_weights.as_slice(),
            program.hidden_biases.as_slice(),
            program.output_weights.as_slice(),
            program.output_biases.as_slice(),
        ],
    )
}

pub fn validate_neural_program(program: &NeuralProgramV1) -> Result<(), NeuralProgramError> {
    let input = usize::from(program.input_width);
    let hidden = usize::from(program.hidden_width);
    let output = usize::from(program.output_width);
    if input == 0
        || input > MAX_L1_NEURAL_INPUTS
        || hidden == 0
        || hidden > MAX_L1_NEURAL_HIDDEN
        || output == 0
        || output > MAX_L1_NEURAL_OUTPUTS
        || program.hidden_weights.len() != input.saturating_mul(hidden)
        || program.hidden_biases.len() != hidden
        || program.output_weights.len() != hidden.saturating_mul(output)
        || program
            .hidden_weights
            .len()
            .checked_add(program.output_weights.len())
            .is_none_or(|weights| weights > MAX_L1_NEURAL_WEIGHTS as usize)
        || program.output_biases.len() != output
    {
        return Err(NeuralProgramError::InvalidShape);
    }
    if program
        .hidden_weights
        .as_slice()
        .iter()
        .chain(program.output_weights.as_slice())
        .any(|value| *value > 2)
    {
        return Err(NeuralProgramError::InvalidTrit);
    }
    if program
        .hidden_biases
        .as_slice()
        .iter()
        .chain(program.output_biases.as_slice())
        .map(|value| *value as i8)
        .any(|value| !(-32..=32).contains(&value))
    {
        return Err(NeuralProgramError::InvalidBias);
    }
    if neural_program_id(program) != program.program_id {
        return Err(NeuralProgramError::InvalidIdentity);
    }
    Ok(())
}

#[inline]
fn decode_trit(value: u8) -> Result<i32, NeuralProgramError> {
    match value {
        0 => Ok(-1),
        1 => Ok(0),
        2 => Ok(1),
        _ => Err(NeuralProgramError::InvalidTrit),
    }
}

#[inline]
fn encode_sign(value: i32) -> u8 {
    match value.cmp(&0) {
        core::cmp::Ordering::Less => 0,
        core::cmp::Ordering::Equal => 1,
        core::cmp::Ordering::Greater => 2,
    }
}

pub fn evaluate_neural_program(
    program: &NeuralProgramV1,
    input: &[u8],
) -> Result<NeuralEvaluation, NeuralProgramError> {
    validate_neural_program(program)?;
    let input_width = usize::from(program.input_width);
    let hidden_width = usize::from(program.hidden_width);
    let output_width = usize::from(program.output_width);
    if input.len() != input_width {
        return Err(NeuralProgramError::InvalidInput);
    }
    let mut inputs = [0_i32; MAX_L1_NEURAL_INPUTS];
    for (index, value) in input.iter().copied().enumerate() {
        inputs[index] = decode_trit(value)?;
    }
    let mut hidden = [0_i32; MAX_L1_NEURAL_HIDDEN];
    for target in 0..hidden_width {
        let mut accumulator = i32::from(program.hidden_biases.as_slice()[target] as i8);
        for (source, value) in inputs[..input_width].iter().enumerate() {
            let weight =
                decode_trit(program.hidden_weights.as_slice()[target * input_width + source])?;
            accumulator = accumulator
                .checked_add(
                    value
                        .checked_mul(weight)
                        .ok_or(NeuralProgramError::Overflow)?,
                )
                .ok_or(NeuralProgramError::Overflow)?;
        }
        hidden[target] = i32::from(encode_sign(accumulator)) - 1;
    }
    let mut output = Vec::with_capacity(output_width);
    for target in 0..output_width {
        let mut accumulator = i32::from(program.output_biases.as_slice()[target] as i8);
        for (source, value) in hidden[..hidden_width].iter().enumerate() {
            let weight =
                decode_trit(program.output_weights.as_slice()[target * hidden_width + source])?;
            accumulator = accumulator
                .checked_add(
                    value
                        .checked_mul(weight)
                        .ok_or(NeuralProgramError::Overflow)?,
                )
                .ok_or(NeuralProgramError::Overflow)?;
        }
        output.push(encode_sign(accumulator));
    }
    let operations = u64::try_from(
        input_width
            .checked_mul(hidden_width)
            .and_then(|value| value.checked_add(hidden_width.checked_mul(output_width)?))
            .and_then(|value| value.checked_add(hidden_width + output_width))
            .ok_or(NeuralProgramError::Overflow)?,
    )
    .map_err(|_| NeuralProgramError::Overflow)?;
    Ok(NeuralEvaluation {
        output: BoundedBytes::new(output).ok_or(NeuralProgramError::Overflow)?,
        operations,
    })
}

#[must_use]
pub fn neural_input_root(input: &[u8]) -> Hash32 {
    domain_hash(domains::NEURAL_ORACLE_INPUT, &[input])
}

#[must_use]
pub fn neural_output_root(response: &[u8]) -> Hash32 {
    *blake3::hash(response).as_bytes()
}

#[must_use]
pub fn neural_transcript_root(response: &[u8]) -> Hash32 {
    domain_hash(domains::NEURAL_ORACLE_TRANSCRIPT, &[response])
}

#[must_use]
pub fn neural_reply_commitment(
    query_id: &Hash32,
    reporter_profile_id: &Hash32,
    output_root: &Hash32,
    transcript_root: &Hash32,
    nonce: &Hash32,
) -> Hash32 {
    domain_hash(
        domains::NEURAL_ORACLE_REPLY_COMMIT,
        &[
            query_id,
            reporter_profile_id,
            output_root,
            transcript_root,
            nonce,
        ],
    )
}

#[must_use]
pub fn neural_result_id(
    query_id: &Hash32,
    output_root: &Hash32,
    transcript_root: &Hash32,
) -> Hash32 {
    domain_hash(
        domains::NEURAL_ORACLE_RESULT,
        &[query_id, output_root, transcript_root],
    )
}

#[must_use]
pub fn neural_program_key(program_id: &Hash32) -> Hash32 {
    domain_hash(domains::NEURAL_ORACLE_PROGRAM_KEY, &[program_id])
}

#[must_use]
pub fn neural_query_key(query_id: &Hash32) -> Hash32 {
    domain_hash(domains::NEURAL_ORACLE_QUERY_KEY, &[query_id])
}

#[must_use]
pub fn neural_commit_key(query_id: &Hash32, reporter_profile_id: &Hash32) -> Hash32 {
    domain_hash(
        domains::NEURAL_ORACLE_COMMIT_KEY,
        &[query_id, reporter_profile_id],
    )
}

#[must_use]
pub fn neural_reveal_key(query_id: &Hash32, reporter_profile_id: &Hash32) -> Hash32 {
    domain_hash(
        domains::NEURAL_ORACLE_REVEAL_KEY,
        &[query_id, reporter_profile_id],
    )
}

#[must_use]
pub fn neural_result_key(query_id: &Hash32) -> Hash32 {
    domain_hash(domains::NEURAL_ORACLE_RESULT_KEY, &[query_id])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identify(mut program: NeuralProgramV1) -> NeuralProgramV1 {
        program.program_id = neural_program_id(&program);
        program
    }

    #[test]
    fn trinary_evaluation_is_exact_and_fully_metered() {
        let program = identify(NeuralProgramV1 {
            program_id: [0; 32],
            input_width: 2,
            hidden_width: 2,
            output_width: 1,
            hidden_weights: BoundedBytes::new(vec![2, 0, 1, 2]).unwrap(),
            hidden_biases: BoundedBytes::new(vec![0, 0]).unwrap(),
            output_weights: BoundedBytes::new(vec![2, 0]).unwrap(),
            output_biases: BoundedBytes::new(vec![0]).unwrap(),
        });
        let evaluation = evaluate_neural_program(&program, &[2, 0]).unwrap();
        assert_eq!(evaluation.output.as_slice(), &[2]);
        assert_eq!(evaluation.operations, 9);
    }

    #[test]
    fn total_weight_bound_rejects_two_individually_bounded_matrices() {
        let program = identify(NeuralProgramV1 {
            program_id: [0; 32],
            input_width: 32,
            hidden_width: 32,
            output_width: 32,
            hidden_weights: BoundedBytes::new(vec![1; 1_024]).unwrap(),
            hidden_biases: BoundedBytes::new(vec![0; 32]).unwrap(),
            output_weights: BoundedBytes::new(vec![1; 1_024]).unwrap(),
            output_biases: BoundedBytes::new(vec![0; 32]).unwrap(),
        });
        assert_eq!(
            validate_neural_program(&program),
            Err(NeuralProgramError::InvalidShape)
        );
    }
}
