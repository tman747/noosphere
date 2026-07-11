//! Honest experiment boundary for `M-HFHE-SUITE`.
//!
//! Exact arithmetic and deterministic circuit encoding are locally testable. They do not supply
//! an IND model, security reduction, concrete attack estimate, refresh prover, independent
//! verifiers, or production parameters, so this module exposes no activation function.

use std::collections::BTreeSet;

pub type Hash32 = [u8; 32];
pub const FIELD_MODULUS: u128 = (1u128 << 127) - 1;
pub const HFHE_CANDIDATE_SUITE: &str = "NOOS/OCTRA-DERIVED-HFHE-CANDIDATE/F127/V1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct F127(u128);

impl F127 {
    pub fn new(value: u128) -> Result<Self, HfheError> {
        if value >= FIELD_MODULUS {
            Err(HfheError::NonCanonicalFieldElement)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }

    pub fn decode(bytes: [u8; 16]) -> Result<Self, HfheError> {
        Self::new(u128::from_le_bytes(bytes))
    }

    #[must_use]
    pub const fn encode(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    #[must_use]
    pub fn add_mod(self, other: Self) -> Self {
        let sum = self.0 + other.0;
        if sum >= FIELD_MODULUS {
            Self(sum - FIELD_MODULUS)
        } else {
            Self(sum)
        }
    }

    /// Exact multiplication by double-and-add. This is a conformance reference, not an
    /// optimized or constant-time cryptographic implementation.
    #[must_use]
    pub fn mul_mod(self, other: Self) -> Self {
        let mut multiplicand = self;
        let mut multiplier = other.0;
        let mut result = Self(0);
        for _ in 0..127 {
            if multiplier & 1 == 1 {
                result = result.add_mod(multiplicand);
            }
            multiplicand = multiplicand.add_mod(multiplicand);
            multiplier >>= 1;
        }
        result
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircuitGate {
    Input(u32),
    Constant(F127),
    Add(u32, u32),
    Mul(u32, u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitCiphertextCandidate {
    pub input_count: u32,
    pub logical_rows: u32,
    pub logical_cols: u32,
    pub gates: Vec<CircuitGate>,
    pub output_gate: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HfheError {
    NonCanonicalFieldElement,
    CircuitShape,
    CircuitReference,
    UnsupportedArithmetic,
    ExternalPrerequisites,
}

impl CircuitCiphertextCandidate {
    pub fn validate(&self) -> Result<(), HfheError> {
        if self.input_count == 0
            || self.logical_rows == 0
            || self.logical_cols == 0
            || self.gates.is_empty()
            || usize::try_from(self.output_gate)
                .ok()
                .is_none_or(|index| index >= self.gates.len())
        {
            return Err(HfheError::CircuitShape);
        }
        for (index, gate) in self.gates.iter().enumerate() {
            let valid_ref = |reference: u32| {
                usize::try_from(reference)
                    .ok()
                    .is_some_and(|reference| reference < index)
            };
            match gate {
                CircuitGate::Input(input) if *input >= self.input_count => {
                    return Err(HfheError::CircuitReference);
                }
                CircuitGate::Add(left, right) | CircuitGate::Mul(left, right)
                    if !valid_ref(*left) || !valid_ref(*right) =>
                {
                    return Err(HfheError::CircuitReference);
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, HfheError> {
        self.validate()?;
        let mut out = b"NOOS/HFHE/CIRCUIT-CIPHERTEXT-CANDIDATE/V1".to_vec();
        for value in [self.input_count, self.logical_rows, self.logical_cols] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        let gate_count = u32::try_from(self.gates.len()).map_err(|_| HfheError::CircuitShape)?;
        out.extend_from_slice(&gate_count.to_le_bytes());
        for gate in &self.gates {
            match gate {
                CircuitGate::Input(input) => {
                    out.push(0);
                    out.extend_from_slice(&input.to_le_bytes());
                }
                CircuitGate::Constant(value) => {
                    out.push(1);
                    out.extend_from_slice(&value.encode());
                }
                CircuitGate::Add(left, right) => {
                    out.push(2);
                    out.extend_from_slice(&left.to_le_bytes());
                    out.extend_from_slice(&right.to_le_bytes());
                }
                CircuitGate::Mul(left, right) => {
                    out.push(3);
                    out.extend_from_slice(&left.to_le_bytes());
                    out.extend_from_slice(&right.to_le_bytes());
                }
            }
        }
        out.extend_from_slice(&self.output_gate.to_le_bytes());
        Ok(out)
    }

    pub fn evaluate(&self, inputs: &[F127]) -> Result<F127, HfheError> {
        self.validate()?;
        if inputs.len() != self.input_count as usize {
            return Err(HfheError::CircuitShape);
        }
        let mut values: Vec<F127> = Vec::with_capacity(self.gates.len());
        for gate in &self.gates {
            let value = match gate {
                CircuitGate::Input(input) => inputs[*input as usize],
                CircuitGate::Constant(value) => *value,
                CircuitGate::Add(left, right) => {
                    values[*left as usize].add_mod(values[*right as usize])
                }
                CircuitGate::Mul(left, right) => {
                    values[*left as usize].mul_mod(values[*right as usize])
                }
            };
            values.push(value);
        }
        Ok(values[self.output_gate as usize])
    }

    pub fn commitment(&self) -> Result<Hash32, HfheError> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HfheCandidateManifest {
    pub suite_name: String,
    pub field_modulus: u128,
    pub deterministic_encoding: bool,
    pub ind_model_root: Option<Hash32>,
    pub reduction_root: Option<Hash32>,
    pub concrete_attack_estimate_bits: Option<u32>,
    pub complete_refresh_prover_root: Option<Hash32>,
    pub verifier_families: BTreeSet<Hash32>,
    pub rotation_rules_root: Option<Hash32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HfheBoundaryReport {
    pub registered: bool,
    pub enabled: bool,
    pub local_exact_arithmetic: bool,
    pub local_deterministic_encoding: bool,
    pub blockers: Vec<&'static str>,
}

#[must_use]
pub fn boundary_report(manifest: &HfheCandidateManifest) -> HfheBoundaryReport {
    let mut blockers = Vec::new();
    if manifest.suite_name != HFHE_CANDIDATE_SUITE
        || manifest.field_modulus != FIELD_MODULUS
        || !manifest.deterministic_encoding
    {
        blockers.push("exact frozen suite and deterministic F_(2^127-1) encoding");
    }
    if manifest.ind_model_root.is_none() {
        blockers.push("IND-style security model");
    }
    if manifest.reduction_root.is_none() {
        blockers.push("standard-assumption reduction");
    }
    if manifest.concrete_attack_estimate_bits.is_none() {
        blockers.push("independent concrete attack estimate");
    }
    if manifest.complete_refresh_prover_root.is_none() {
        blockers.push("complete public refresh prover");
    }
    if manifest.verifier_families.len() < 2 {
        blockers.push("two independent verifier families");
    }
    if manifest.rotation_rules_root.is_none() {
        blockers.push("key rotation and compromise rules");
    }
    HfheBoundaryReport {
        registered: false,
        enabled: false,
        local_exact_arithmetic: manifest.field_modulus == FIELD_MODULUS,
        local_deterministic_encoding: manifest.deterministic_encoding,
        blockers,
    }
}

/// There is intentionally no locally satisfiable activation path. Even a structurally complete
/// manifest needs independent cryptanalysis and verifier provenance outside this crate.
pub fn reject_local_activation(_: &HfheCandidateManifest) -> Result<(), HfheError> {
    Err(HfheError::ExternalPrerequisites)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    fn candidate() -> HfheCandidateManifest {
        HfheCandidateManifest {
            suite_name: HFHE_CANDIDATE_SUITE.into(),
            field_modulus: FIELD_MODULUS,
            deterministic_encoding: true,
            ind_model_root: None,
            reduction_root: None,
            concrete_attack_estimate_bits: None,
            complete_refresh_prover_root: None,
            verifier_families: BTreeSet::new(),
            rotation_rules_root: None,
        }
    }

    fn circuit(rows: u32, cols: u32) -> CircuitCiphertextCandidate {
        CircuitCiphertextCandidate {
            input_count: 2,
            logical_rows: rows,
            logical_cols: cols,
            gates: vec![
                CircuitGate::Input(0),
                CircuitGate::Input(1),
                CircuitGate::Mul(0, 1),
                CircuitGate::Add(2, 0),
            ],
            output_gate: 3,
        }
    }

    #[test]
    fn exact_mersenne_field_arithmetic_and_encoding() {
        let max = F127::new(FIELD_MODULUS - 1).unwrap();
        let two = F127::new(2).unwrap();
        assert_eq!(max.add_mod(two), F127::new(1).unwrap());
        assert_eq!(max.mul_mod(max), F127::new(1).unwrap());
        let value = F127::new(123_456_789).unwrap();
        assert_eq!(F127::decode(value.encode()), Ok(value));
        assert_eq!(
            F127::new(FIELD_MODULUS),
            Err(HfheError::NonCanonicalFieldElement)
        );
    }

    #[test]
    fn ciphertext_as_circuit_is_exact_but_is_not_a_security_claim() {
        let c = circuit(1, 1);
        let x = F127::new(9).unwrap();
        let y = F127::new(7).unwrap();
        assert_eq!(c.evaluate(&[x, y]), Ok(F127::new(72).unwrap()));
        let report = boundary_report(&candidate());
        assert!(report.local_exact_arithmetic);
        assert!(report.local_deterministic_encoding);
        assert!(!report.registered);
        assert!(!report.enabled);
        assert!(report.blockers.contains(&"IND-style security model"));
        assert_eq!(
            reject_local_activation(&candidate()),
            Err(HfheError::ExternalPrerequisites)
        );
    }

    #[test]
    fn shape_and_gate_encoding_are_unambiguous_and_splice_resistant() {
        let one_by_two = circuit(1, 2);
        let two_by_one = circuit(2, 1);
        assert_ne!(one_by_two.encode().unwrap(), two_by_one.encode().unwrap());
        assert_ne!(
            one_by_two.commitment().unwrap(),
            two_by_one.commitment().unwrap()
        );
        let mut spliced = one_by_two.clone();
        spliced.gates[2] = CircuitGate::Mul(2, 1);
        assert_eq!(spliced.validate(), Err(HfheError::CircuitReference));
    }

    #[test]
    fn downgrade_to_wrong_field_or_toy_lattice_never_enables_suite() {
        let mut wrong = candidate();
        wrong.field_modulus = u128::from(u64::MAX);
        let report = boundary_report(&wrong);
        assert!(!report.local_exact_arithmetic);
        assert!(!report.registered);
        assert!(!report.enabled);
        assert_eq!(
            reject_local_activation(&wrong),
            Err(HfheError::ExternalPrerequisites)
        );
    }
}
