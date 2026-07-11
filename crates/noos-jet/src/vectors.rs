//! Golden fixtures for `protocol/vectors/jet/` (frozen before G1).
//!
//! This module is the single source of truth: the `jet-vec` binary
//! serializes these tables to JSON, the crate tests byte-compare the
//! committed files against fresh emission AND re-execute every case
//! against the interpreter/lowerer, so a semantics regression fails tests
//! instead of silently regenerating different fixtures.

use noos_grain::{encode_noun, eval, eval_with_jets, Meter, Noun};

use crate::jets::{
    inc_formula, jet_inc, jet_tree_eq, tree_eq_formula, INC_IMPL_TAG, TREE_EQ_IMPL_TAG,
};
use crate::registry::{JetRegistry, NativeJet};
use crate::rv32::{execute, lower, subject_noun};

/// Frozen corpus seed for the shipped jet certificates ("NOOSJET1").
pub const CERT_CORPUS_SEED: u64 = 0x4E4F_4F53_4A45_5431;
/// Frozen corpus size for the shipped jet certificates.
pub const CERT_CASE_COUNT: u32 = 1024;
/// Step bound used for every golden RV32 run (far above any lowered case).
pub const RV32_MAX_STEPS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Shared fixture data
// ---------------------------------------------------------------------------

/// One shipped jet: name, versioned tag, frozen formula, native impl.
pub struct JetSpec {
    pub name: &'static str,
    pub impl_tag: &'static str,
    pub formula: Noun,
    pub native: NativeJet,
}

/// The two admitted jets (M-JET pass shape: one bounded field jet, one
/// tree jet).
#[must_use]
pub fn jet_specs() -> Vec<JetSpec> {
    vec![
        JetSpec {
            name: "inc",
            impl_tag: INC_IMPL_TAG,
            formula: inc_formula(),
            native: jet_inc,
        },
        JetSpec {
            name: "tree_eq",
            impl_tag: TREE_EQ_IMPL_TAG,
            formula: tree_eq_formula(),
            native: jet_tree_eq,
        },
    ]
}

/// The registry with both shipped jets certified and admitted under the
/// frozen corpus parameters.
#[must_use]
pub fn shipped_registry() -> JetRegistry {
    let mut reg = JetRegistry::new();
    for spec in jet_specs() {
        let cert = match JetRegistry::certify(
            &spec.formula,
            spec.impl_tag,
            spec.native,
            CERT_CORPUS_SEED,
            CERT_CASE_COUNT,
        ) {
            Ok(c) => c,
            Err(e) => unreachable!("shipped jet {} failed certification: {e}", spec.name),
        };
        if let Err(e) = reg.admit(cert, spec.native) {
            unreachable!("shipped jet {} failed admission: {e}", spec.name);
        }
    }
    reg
}

// ---------------------------------------------------------------------------
// Noun-building helpers
// ---------------------------------------------------------------------------

fn a(v: u64) -> Noun {
    Noun::atom_u64(v)
}

fn c2(h: Noun, t: Noun) -> Noun {
    match Noun::cell(h, t) {
        Ok(n) => n,
        Err(_) => unreachable!("fixture noun exceeds frozen depth"),
    }
}

fn c3(x: Noun, y: Noun, z: Noun) -> Noun {
    c2(x, c2(y, z))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// jet-cert-v1
// ---------------------------------------------------------------------------

/// `jet-cert-v1.json`: the shipped certificates, every field frozen.
#[must_use]
pub fn cert_json() -> String {
    let mut out = String::new();
    out.push_str("{\"schema\":\"noos/jet/cert-v1\",\"cert_version\":1,\"cases\":[");
    let mut first = true;
    for spec in jet_specs() {
        let cert = match JetRegistry::certify(
            &spec.formula,
            spec.impl_tag,
            spec.native,
            CERT_CORPUS_SEED,
            CERT_CASE_COUNT,
        ) {
            Ok(c) => c,
            Err(e) => unreachable!("shipped jet {} failed certification: {e}", spec.name),
        };
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"kind\":\"positive\",\"bytes\":\"{}\",\"impl_tag\":\"{}\",\"formula\":\"{}\",\"semantics_hash\":\"{}\",\"jet_id\":\"{}\",\"corpus_seed\":{},\"case_count\":{},\"corpus_root\":\"{}\",\"cert_digest\":\"{}\"}}",
            spec.name,
            hex(&cert.canonical_bytes()),
            cert.impl_tag,
            hex(&cert.formula),
            hex(&cert.semantics_hash.0),
            hex(&cert.jet_id.0),
            cert.equivalence.corpus_seed,
            cert.equivalence.case_count,
            hex(&cert.equivalence.corpus_root),
            hex(&cert.digest),
        ));
    }
    out.push_str("]}\n");
    out
}

// ---------------------------------------------------------------------------
// jet-rv32-lowering-v1
// ---------------------------------------------------------------------------

/// One golden lowering case: a formula, the declared tuple width, and the
/// input runs whose journals are frozen.
pub struct Rv32Case {
    pub name: &'static str,
    pub formula: Noun,
    pub leaf_count: u32,
    pub runs: Vec<Vec<u32>>,
}

/// The frozen lowering cases (every grammar production and both exits).
#[must_use]
pub fn rv32_cases() -> Vec<Rv32Case> {
    vec![
        Rv32Case {
            name: "const42",
            formula: c2(a(1), a(42)),
            leaf_count: 1,
            runs: vec![vec![7]],
        },
        Rv32Case {
            name: "slot_first_of3",
            formula: c2(a(0), a(2)),
            leaf_count: 3,
            runs: vec![vec![11, 22, 33]],
        },
        Rv32Case {
            name: "slot_last_of3",
            formula: c2(a(0), a(7)),
            leaf_count: 3,
            runs: vec![vec![11, 22, 33]],
        },
        Rv32Case {
            name: "inc_leaf",
            formula: c2(a(4), c2(a(0), a(1))),
            leaf_count: 1,
            runs: vec![vec![5], vec![0], vec![u32::MAX]],
        },
        Rv32Case {
            name: "eq_leaves",
            formula: c3(a(5), c2(a(0), a(2)), c2(a(0), a(3))),
            leaf_count: 2,
            runs: vec![vec![9, 9], vec![9, 10]],
        },
        Rv32Case {
            name: "if_eq_then_inc_else_zero",
            formula: c2(
                a(6),
                c3(
                    c3(a(5), c2(a(0), a(2)), c2(a(0), a(3))),
                    c2(a(4), c2(a(0), a(2))),
                    c2(a(1), a(0)),
                ),
            ),
            leaf_count: 2,
            runs: vec![vec![4, 4], vec![4, 9]],
        },
        Rv32Case {
            name: "if_nonloobean_domain_exit",
            formula: c2(a(6), c3(c2(a(0), a(2)), c2(a(1), a(1)), c2(a(1), a(2)))),
            leaf_count: 2,
            runs: vec![vec![5, 9], vec![0, 9], vec![1, 9]],
        },
        Rv32Case {
            name: "nested_inc_eq",
            formula: c3(a(5), c2(a(4), c2(a(0), a(2))), c2(a(0), a(3))),
            leaf_count: 2,
            runs: vec![vec![4, 5], vec![4, 9], vec![u32::MAX, 0]],
        },
    ]
}

/// `jet-rv32-lowering-v1.json`: byte-exact images, image ids, and journals.
#[must_use]
pub fn rv32_json() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{{\"schema\":\"noos/jet/rv32-lowering-v1\",\"abi_version\":{},\"max_steps\":{RV32_MAX_STEPS},\"cases\":[",
        crate::rv32::RV32_ABI_VERSION
    ));
    let mut first_case = true;
    for case in rv32_cases() {
        let image = match lower(&case.formula, case.leaf_count) {
            Ok(i) => i,
            Err(e) => unreachable!("golden case {} failed to lower: {e}", case.name),
        };
        if !first_case {
            out.push(',');
        }
        first_case = false;
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"kind\":\"positive\",\"bytes\":\"{}\",\"formula\":\"{}\",\"leaf_count\":{},\"image_id\":\"{}\",\"runs\":[",
            case.name,
            hex(&image.bytes()),
            hex(&encode_noun(&case.formula)),
            case.leaf_count,
            hex(&image.image_id()),
        ));
        let mut first_run = true;
        for leaves in &case.runs {
            let exit = match execute(&image, leaves, RV32_MAX_STEPS) {
                Ok(e) => e,
                Err(t) => unreachable!("golden case {} trapped: {t}", case.name),
            };
            if !first_run {
                out.push(',');
            }
            first_run = false;
            let leaves_json = leaves
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!(
                "{{\"leaves\":[{leaves_json}],\"status\":{},\"value\":{}}}",
                exit.status, exit.value
            ));
        }
        out.push_str("]}");
    }
    out.push_str("]}\n");
    out
}

// ---------------------------------------------------------------------------
// jet-dispatch-v1
// ---------------------------------------------------------------------------

/// Evaluation mode of a dispatch case.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Production `eval`: no hook exists, opcode 12 is `UNKNOWN_OPCODE`.
    Production,
    /// `eval_with_jets` over the shipped registry.
    Hooked,
}

/// One golden dispatch case (expectations are derived at emission and
/// frozen in the committed file).
pub struct DispatchCase {
    pub name: &'static str,
    pub mode: Mode,
    pub subject: Noun,
    pub formula: Noun,
    pub meter_limit: u64,
    pub arena_limit: u64,
}

fn hint(id: &Noun, f: &Noun) -> Noun {
    c3(a(12), id.clone(), f.clone())
}

/// The frozen dispatch cases: fired jets, both fallback laws, production
/// rejection, and mid-schedule exhaustion.
#[must_use]
pub fn dispatch_cases() -> Vec<DispatchCase> {
    let inc_sem = crate::cert::semantics_hash(&inc_formula());
    let inc_id = crate::cert::jet_id(&inc_sem, INC_IMPL_TAG).as_noun();
    let eq_sem = crate::cert::semantics_hash(&tree_eq_formula());
    let eq_id = crate::cert::jet_id(&eq_sem, TREE_EQ_IMPL_TAG).as_noun();
    vec![
        DispatchCase {
            name: "hooked_inc_fires",
            mode: Mode::Hooked,
            subject: a(5),
            formula: hint(&inc_id, &inc_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_inc_zero_subject",
            mode: Mode::Hooked,
            subject: a(0),
            formula: hint(&inc_id, &inc_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_inc_cell_subject_type_mismatch",
            mode: Mode::Hooked,
            subject: c2(a(1), a(2)),
            formula: hint(&inc_id, &inc_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_tree_eq_equal",
            mode: Mode::Hooked,
            subject: c2(c2(a(1), a(2)), c2(a(1), a(2))),
            formula: hint(&eq_id, &tree_eq_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_tree_eq_unequal",
            mode: Mode::Hooked,
            subject: c2(a(7), a(8)),
            formula: hint(&eq_id, &tree_eq_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_unknown_id_falls_back",
            mode: Mode::Hooked,
            subject: a(5),
            formula: hint(&a(0xDEAD), &inc_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_semantics_mismatch_falls_back",
            mode: Mode::Hooked,
            subject: c2(a(7), a(7)),
            formula: hint(&inc_id, &tree_eq_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "hooked_inc_meter_exhaustion_pins_spent",
            mode: Mode::Hooked,
            subject: a(5),
            formula: hint(&inc_id, &inc_formula()),
            meter_limit: 3,
            arena_limit: 1_000,
        },
        DispatchCase {
            name: "production_op12_unknown_opcode",
            mode: Mode::Production,
            subject: a(5),
            formula: hint(&inc_id, &inc_formula()),
            meter_limit: 1_000,
            arena_limit: 1_000,
        },
    ]
}

/// Run one dispatch case; returns (outcome, spent, arena).
pub fn run_dispatch_case(
    case: &DispatchCase,
    reg: &JetRegistry,
) -> (Result<Vec<u8>, u16>, u64, u64) {
    let mut meter = Meter::new(case.meter_limit, case.arena_limit);
    let r = match case.mode {
        Mode::Production => eval(1, case.subject.clone(), case.formula.clone(), &mut meter),
        Mode::Hooked => eval_with_jets(
            1,
            case.subject.clone(),
            case.formula.clone(),
            &mut meter,
            reg,
        ),
    };
    (
        r.map(|n| encode_noun(&n))
            .map_err(noos_grain::GrainTrap::code),
        meter.spent(),
        meter.arena_used(),
    )
}

/// `jet-dispatch-v1.json`: observational triples of the dispatch law.
#[must_use]
pub fn dispatch_json() -> String {
    let reg = shipped_registry();
    let mut out = String::new();
    out.push_str("{\"schema\":\"noos/jet/dispatch-v1\",\"cases\":[");
    let mut first = true;
    for case in dispatch_cases() {
        let (outcome, spent, arena) = run_dispatch_case(&case, &reg);
        if !first {
            out.push(',');
        }
        first = false;
        let mode = match case.mode {
            Mode::Production => "production",
            Mode::Hooked => "hooked",
        };
        // Gate schema: value outcomes are positive cases carrying the
        // encoded result noun as `bytes`; traps are negative cases with an
        // empty payload and the stable trap code.
        let (kind, bytes, outcome_json) = match &outcome {
            Ok(v) => ("positive", hex(v), String::new()),
            Err(code) => ("negative", String::new(), format!("\"trap\":{code},")),
        };
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"kind\":\"{kind}\",\"bytes\":\"{bytes}\",\"mode\":\"{mode}\",\"subject\":\"{}\",\"formula\":\"{}\",\"meter_limit\":{},\"arena_limit\":{},{outcome_json}\"charge\":{spent},\"arena\":{arena}}}",
            case.name,
            hex(&encode_noun(&case.subject)),
            hex(&encode_noun(&case.formula)),
            case.meter_limit,
            case.arena_limit,
        ));
    }
    out.push_str("]}\n");
    out
}

/// Every golden file this crate owns, in emission order.
#[must_use]
pub fn vector_files() -> Vec<(&'static str, String)> {
    vec![
        ("jet-cert-v1.json", cert_json()),
        ("jet-rv32-lowering-v1.json", rv32_json()),
        ("jet-dispatch-v1.json", dispatch_json()),
    ]
}

/// Convenience for tests: the frozen subject noun of an RV32 run.
#[must_use]
pub fn rv32_subject(leaves: &[u32]) -> Noun {
    subject_noun(leaves)
}

/// Reproducible binding vector for the real RISC Zero guest. The vector pins
/// the compiled method id/ELF digest and exact private-input/public-journal
/// bytes. It intentionally does not embed or characterize a generated proof;
/// the dedicated claim runner performs real CPU proving and verification.
#[cfg(feature = "risc0")]
#[must_use]
pub fn risc0_json() -> String {
    use crate::architecture::ProofArchitectureManifest;
    use crate::cert::{jet_id, semantics_hash};
    use crate::risc0::{risc0_method_id, Risc0ProofContext, Risc0ProofInput};

    let registry = shipped_registry();
    let formula = inc_formula();
    let id = jet_id(&semantics_hash(&formula), INC_IMPL_TAG);
    let image = match lower(&formula, 1) {
        Ok(image) => image,
        Err(error) => unreachable!("shipped inc lowering failed: {error}"),
    };
    let profile = ProofArchitectureManifest {
        numeric_profile: [0x11; 32],
        checkpoint: [0x22; 32],
        activation_commitment: [0x33; 32],
        projection_hook: [0x44; 32],
        moe_route_policy: [0x55; 32],
        tolerance_ppm: 250,
    };
    let context = Risc0ProofContext {
        chain_id: [0x91; 32],
        domain: [0x92; 32],
        profile_id: profile.profile_id(),
    };
    let input =
        match Risc0ProofInput::certified(&registry, &id, &image, &[41], context, RV32_MAX_STEPS) {
            Ok(input) => input,
            Err(error) => unreachable!("shipped RISC Zero vector failed: {error}"),
        };
    let method_words = risc0_method_id()
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let guest_input = input.canonical_guest_input();
    let claim_bytes = input.request().claim.canonical_bytes();
    let elf_digest = blake3::hash(noos_jet_risc0_methods::JET_PROOF_ELF);
    let input_digest = blake3::hash(&guest_input);
    let claim_digest = blake3::hash(&claim_bytes);
    format!(
        "{{\"schema\":\"noos/jet/risc0-proof-v1\",\"sdk_version\":\"3.0.5\",\"guest_build\":\"risc0-guest-builder-r0.1.88.0\",\"receipt_kind\":\"composite\",\"method_id_words\":[{method_words}],\"guest_elf_blake3\":\"{}\",\"cases\":[{{\"name\":\"certified_inc_41\",\"kind\":\"positive\",\"chain_id\":\"{}\",\"domain\":\"{}\",\"profile_id\":\"{}\",\"jet_id\":\"{}\",\"semantics_hash\":\"{}\",\"cert_digest\":\"{}\",\"rv32_image_id\":\"{}\",\"rv32_image_bytes\":\"{}\",\"leaves\":[41],\"guest_input\":\"{}\",\"guest_input_blake3\":\"{}\",\"journal\":\"{}\",\"journal_blake3\":\"{}\",\"status\":{},\"value\":{},\"steps\":{}}}]}}\n",
        hex(elf_digest.as_bytes()),
        hex(&context.chain_id),
        hex(&context.domain),
        hex(&context.profile_id),
        hex(&input.request().claim.jet_id),
        hex(&input.request().claim.semantics_hash),
        hex(&input.request().claim.cert_digest),
        hex(&input.request().claim.rv32_image_id),
        hex(&image.bytes()),
        hex(&guest_input),
        hex(input_digest.as_bytes()),
        hex(&claim_bytes),
        hex(claim_digest.as_bytes()),
        input.request().claim.status,
        input.request().claim.value,
        input.request().claim.steps,
    )
}
