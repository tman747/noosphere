#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use core::cell::Cell;

use noos_grain::{encode_noun, eval, eval_with_jets, GrainTrap, JetHook, Meter, Noun};

use crate::architecture::{
    artifact_id, work_commit, CommitmentDeclaration, CommitmentError, ProofArchitectureManifest,
};
#[cfg(feature = "risc0")]
use crate::cert::JetId;
use crate::cert::{jet_id, semantics_hash, JetCert};
use crate::corpus::{self, SplitMix64};
use crate::jets::{
    inc_formula, jet_inc, jet_tree_eq, tree_eq_formula, INC_IMPL_TAG, TREE_EQ_IMPL_TAG,
};
use crate::proof::{
    input_commit, prove_local, LocalExecutionChecker, LocalReceipt, ProofError, ProofRequest,
    ReceiptVerifier,
};
use crate::registry::{AdmitError, JetRegistry};
use crate::rv32::{
    axis_of_leaf, execute, lower, subject_noun, Rv32Image, Rv32Trap, MAX_LEAVES, RV32_ABI_VERSION,
};
use crate::vectors::{self, Mode, CERT_CASE_COUNT, CERT_CORPUS_SEED, RV32_MAX_STEPS};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn a(v: u64) -> Noun {
    Noun::atom_u64(v)
}

fn c2(h: Noun, t: Noun) -> Noun {
    Noun::cell(h, t).unwrap()
}

fn c3(x: Noun, y: Noun, z: Noun) -> Noun {
    c2(x, c2(y, z))
}

type Triple = (Result<Vec<u8>, u16>, u64, u64);

fn interp(s: &Noun, f: &Noun, steps: u64, arena: u64) -> Triple {
    let mut m = Meter::new(steps, arena);
    let r = eval(1, s.clone(), f.clone(), &mut m);
    (
        r.map(|n| encode_noun(&n)).map_err(GrainTrap::code),
        m.spent(),
        m.arena_used(),
    )
}

fn jetted(s: &Noun, f: &Noun, steps: u64, arena: u64, hook: &dyn JetHook) -> Triple {
    let mut m = Meter::new(steps, arena);
    let r = eval_with_jets(1, s.clone(), f.clone(), &mut m, hook);
    (
        r.map(|n| encode_noun(&n)).map_err(GrainTrap::code),
        m.spent(),
        m.arena_used(),
    )
}

fn inc_cert() -> JetCert {
    JetRegistry::certify(
        &inc_formula(),
        INC_IMPL_TAG,
        jet_inc,
        CERT_CORPUS_SEED,
        CERT_CASE_COUNT,
    )
    .unwrap()
}

fn hint(id: &Noun, f: &Noun) -> Noun {
    c3(a(12), id.clone(), f.clone())
}

/// Delegating hook that counts how often the inner registry actually fires,
/// so corpus tests PROVE the jet ran instead of silently falling back.
struct Counting<'a> {
    inner: &'a JetRegistry,
    fired: Cell<u64>,
}

impl JetHook for Counting<'_> {
    fn dispatch(
        &self,
        id: &Noun,
        subject: &Noun,
        formula: &Noun,
        meter: &mut Meter,
    ) -> Option<Result<Noun, GrainTrap>> {
        let r = self.inner.dispatch(id, subject, formula, meter);
        if r.is_some() {
            self.fired.set(self.fired.get() + 1);
        }
        r
    }
}

// ---------------------------------------------------------------------------
// Certification and admission (M-JET / A-JET-CERT falsifiers)
// ---------------------------------------------------------------------------

#[test]
fn shipped_jets_certify_and_admit() {
    let reg = vectors::shipped_registry();
    assert_eq!(reg.len(), 2);
    let inc = jet_id(&semantics_hash(&inc_formula()), INC_IMPL_TAG);
    let eq = jet_id(&semantics_hash(&tree_eq_formula()), TREE_EQ_IMPL_TAG);
    assert!(reg.cert(&inc).is_some());
    assert!(reg.cert(&eq).is_some());
}

#[test]
fn forged_certificate_digest_is_rejected() {
    // Tampering any committed field without recomputing the digest fails
    // the binding commitment.
    let mut cert = inc_cert();
    cert.equivalence.corpus_root[0] ^= 1;
    let mut reg = JetRegistry::new();
    assert_eq!(reg.admit(cert, jet_inc), Err(AdmitError::DigestMismatch));
    assert!(reg.is_empty());
}

#[test]
fn forged_equivalence_root_is_rejected_even_with_recomputed_digest() {
    // The digest is a commitment, not an authority: an adversary CAN
    // recompute it over forged fields. Corpus replay still rejects.
    let mut cert = inc_cert();
    cert.equivalence.corpus_root[0] ^= 1;
    cert.digest = cert.compute_digest();
    let mut reg = JetRegistry::new();
    assert_eq!(
        reg.admit(cert, jet_inc),
        Err(AdmitError::EquivalenceRootMismatch)
    );
}

#[test]
fn semantics_hash_mismatch_is_rejected() {
    // A certificate whose formula bytes do not hash to its stated
    // semantics hash never enters the registry.
    let mut cert = inc_cert();
    cert.formula = encode_noun(&tree_eq_formula());
    cert.digest = cert.compute_digest();
    let mut reg = JetRegistry::new();
    assert_eq!(
        reg.admit(cert, jet_inc),
        Err(AdmitError::SemanticsHashMismatch)
    );
}

#[test]
fn impl_tag_tamper_changes_jet_id_and_is_rejected() {
    let mut cert = inc_cert();
    cert.impl_tag = "noos-jet/native/inc/v2".to_owned();
    cert.digest = cert.compute_digest();
    let mut reg = JetRegistry::new();
    assert_eq!(reg.admit(cert, jet_inc), Err(AdmitError::JetIdMismatch));
}

#[test]
fn unsupported_cert_version_is_rejected() {
    let mut cert = inc_cert();
    cert.cert_version = 2;
    cert.digest = cert.compute_digest();
    let mut reg = JetRegistry::new();
    assert_eq!(
        reg.admit(cert, jet_inc),
        Err(AdmitError::UnsupportedCertVersion(2))
    );
}

#[test]
fn divergent_native_cannot_certify_and_cannot_be_admitted() {
    // tree-eq native against the inc formula: certification refuses.
    assert!(JetRegistry::certify(
        &inc_formula(),
        INC_IMPL_TAG,
        jet_tree_eq,
        CERT_CORPUS_SEED,
        CERT_CASE_COUNT
    )
    .is_err());
    // A perfectly valid inc certificate cannot smuggle in a different
    // native implementation either: replay diverges.
    let mut reg = JetRegistry::new();
    match reg.admit(inc_cert(), jet_tree_eq) {
        Err(AdmitError::EquivalenceDivergence { .. }) => {}
        other => panic!("expected divergence, got {other:?}"),
    }
}

#[test]
fn duplicate_admission_is_rejected() {
    let mut reg = JetRegistry::new();
    reg.admit(inc_cert(), jet_inc).unwrap();
    assert_eq!(
        reg.admit(inc_cert(), jet_inc),
        Err(AdmitError::DuplicateJetId)
    );
}

// ---------------------------------------------------------------------------
// Dispatch law: an uncertified jet NEVER fires
// ---------------------------------------------------------------------------

#[test]
fn dispatch_never_fires_an_uncertified_id() {
    let reg = vectors::shipped_registry();
    let mut m = Meter::new(1_000, 1_000);
    // Unknown id: declined at the hook level.
    assert!(reg
        .dispatch(&a(0xDEAD_BEEF), &a(5), &inc_formula(), &mut m)
        .is_none());
    // Cell id: declined.
    assert!(reg
        .dispatch(&c2(a(1), a(2)), &a(5), &inc_formula(), &mut m)
        .is_none());
    assert_eq!(m.spent(), 0);

    // End to end: the fallback interprets f with the identical triple.
    let f = hint(&a(0xDEAD_BEEF), &inc_formula());
    assert_eq!(
        jetted(&a(5), &f, 1_000, 1_000, &reg),
        interp(&a(5), &inc_formula(), 1_000, 1_000)
    );
}

#[test]
fn dispatch_never_fires_a_certified_id_on_different_semantics() {
    let reg = vectors::shipped_registry();
    let inc_id = jet_id(&semantics_hash(&inc_formula()), INC_IMPL_TAG).as_noun();
    let mut m = Meter::new(1_000, 1_000);
    // The inc id offered the tree-eq formula: semantics hash differs,
    // the hook declines, the meter is untouched.
    assert!(reg
        .dispatch(&inc_id, &c2(a(7), a(7)), &tree_eq_formula(), &mut m)
        .is_none());
    assert_eq!(m.spent(), 0);

    // End to end the fallback is exact interpretation of the OFFERED f.
    let s = c2(a(7), a(7));
    let f = hint(&inc_id, &tree_eq_formula());
    assert_eq!(
        jetted(&s, &f, 1_000, 1_000, &reg),
        interp(&s, &tree_eq_formula(), 1_000, 1_000)
    );
}

#[test]
fn dispatch_fires_on_the_certified_pair() {
    let reg = vectors::shipped_registry();
    let inc_id = jet_id(&semantics_hash(&inc_formula()), INC_IMPL_TAG).as_noun();
    let mut m = Meter::new(1_000, 1_000);
    let r = reg.dispatch(&inc_id, &a(5), &inc_formula(), &mut m);
    assert_eq!(r, Some(Ok(a(6))));
}

// ---------------------------------------------------------------------------
// Fallback equality: jet output == interpreted Grain output, seeded corpus
// ---------------------------------------------------------------------------

/// Frozen charge literals (hand-derived from the spec cost table) pin the
/// mirrored schedule against silent cost regressions.
#[test]
fn jet_charges_match_frozen_literals() {
    // inc of atom 0: slot 2 + inc (2 + 0) + alloc (1 + 1) = 6, arena 2.
    let mut m = Meter::new(1_000, 1_000);
    assert_eq!(jet_inc(&a(0), &mut m), Ok(a(1)));
    assert_eq!((m.spent(), m.arena_used()), (6, 2));
    // tree-eq of [5 5]: slot 3 + slot 3 + base 2 + node 1 + word 1 = 10.
    let mut m = Meter::new(1_000, 1_000);
    assert_eq!(jet_tree_eq(&c2(a(5), a(5)), &mut m), Ok(a(0)));
    assert_eq!((m.spent(), m.arena_used()), (10, 0));
}

#[test]
fn jet_output_equals_interpreted_grain_on_seeded_corpus() {
    // An INDEPENDENT seed from the certification corpus: 1200 cases per
    // jet, tight/medium/roomy meters, boundary-heavy subjects. The
    // counting hook proves the jet actually fired on every case.
    const SEED: u64 = 0x4A45_5450_524F_4F46; // "JETPROOF"
    const CASES: u32 = 1_200;
    let reg = vectors::shipped_registry();
    for (formula, tag) in [
        (inc_formula(), INC_IMPL_TAG),
        (tree_eq_formula(), TREE_EQ_IMPL_TAG),
    ] {
        let id = jet_id(&semantics_hash(&formula), tag).as_noun();
        let hinted = hint(&id, &formula);
        let counting = Counting {
            inner: &reg,
            fired: Cell::new(0),
        };
        for index in 0..CASES {
            let case = corpus::case(SEED, index);
            let want = interp(&case.subject, &formula, case.step_limit, case.arena_limit);
            let got = jetted(
                &case.subject,
                &hinted,
                case.step_limit,
                case.arena_limit,
                &counting,
            );
            assert_eq!(want, got, "jet {tag} diverged on corpus case {index}");
        }
        assert_eq!(
            counting.fired.get(),
            u64::from(CASES),
            "jet {tag} did not fire"
        );
    }
}

#[test]
fn hooked_dispatch_cases_equal_erased_interpretation() {
    // Every hooked golden case obeys the erasure law: [12 id f] under the
    // shipped registry == plain eval of f, triple-exact.
    let reg = vectors::shipped_registry();
    for case in vectors::dispatch_cases() {
        if case.mode != Mode::Hooked {
            continue;
        }
        let (_, erased) = case
            .formula
            .as_cell()
            .and_then(|(_, t)| t.as_cell())
            .map(|(h, t)| (h.clone(), t.clone()))
            .unwrap();
        assert_eq!(
            jetted(
                &case.subject,
                &case.formula,
                case.meter_limit,
                case.arena_limit,
                &reg
            ),
            interp(&case.subject, &erased, case.meter_limit, case.arena_limit),
            "dispatch case {} broke the erasure law",
            case.name
        );
    }
}

#[test]
fn production_dispatch_case_stays_unknown_opcode() {
    for case in vectors::dispatch_cases() {
        if case.mode != Mode::Production {
            continue;
        }
        let (outcome, spent, arena) = interp(
            &case.subject,
            &case.formula,
            case.meter_limit,
            case.arena_limit,
        );
        assert_eq!(outcome, Err(GrainTrap::UnknownOpcode.code()));
        assert_eq!((spent, arena), (0, 0));
    }
}

// ---------------------------------------------------------------------------
// RV32 lowering ABI
// ---------------------------------------------------------------------------

#[test]
fn rv32_lowering_is_deterministic() {
    for case in vectors::rv32_cases() {
        let x = lower(&case.formula, case.leaf_count).unwrap();
        let y = lower(&case.formula, case.leaf_count).unwrap();
        assert_eq!(x, y);
        assert_eq!(x.image_id(), y.image_id());
    }
}

#[test]
fn rv32_golden_cases_execute_and_never_answer_wrongly() {
    let mut saw_domain_exit = false;
    for case in vectors::rv32_cases() {
        let image = lower(&case.formula, case.leaf_count).unwrap();
        for leaves in &case.runs {
            let exit = execute(&image, leaves, RV32_MAX_STEPS).unwrap();
            let subject = subject_noun(leaves);
            match exit.status {
                0 => {
                    // Soundness: status 0 must equal Grain exactly.
                    let mut m = Meter::new(1_000_000, 1_000_000);
                    let want = eval(1, subject, case.formula.clone(), &mut m).unwrap();
                    assert_eq!(
                        want,
                        a(u64::from(exit.value)),
                        "case {} leaves {leaves:?}",
                        case.name
                    );
                }
                1 => {
                    assert_eq!(exit.value, 0, "domain exit must zero a0");
                    saw_domain_exit = true;
                }
                other => panic!("case {}: invalid status {other}", case.name),
            }
        }
    }
    assert!(saw_domain_exit, "golden set must exercise the domain exit");
}

#[test]
fn rv32_known_domain_exits() {
    // Increment past u32::MAX and a non-loobean condition both domain-exit.
    let inc = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    assert_eq!(
        execute(&inc, &[u32::MAX], RV32_MAX_STEPS).unwrap().status,
        1
    );
    assert_eq!(execute(&inc, &[41], RV32_MAX_STEPS).unwrap().value, 42);
    let iff = lower(
        &c2(a(6), c3(c2(a(0), a(2)), c2(a(1), a(1)), c2(a(1), a(2)))),
        2,
    )
    .unwrap();
    assert_eq!(execute(&iff, &[5, 9], RV32_MAX_STEPS).unwrap().status, 1);
    assert_eq!(execute(&iff, &[0, 9], RV32_MAX_STEPS).unwrap().value, 1);
    assert_eq!(execute(&iff, &[1, 9], RV32_MAX_STEPS).unwrap().value, 2);
}

/// Deterministic random formula in the lowered grammar.
fn random_formula(rng: &mut SplitMix64, leaf_count: u32, depth: u32) -> Noun {
    let leaf = |rng: &mut SplitMix64| {
        if rng.below(2) == 0 {
            let i = u32::try_from(rng.below(u64::from(leaf_count))).unwrap();
            c2(a(0), a(axis_of_leaf(i, leaf_count)))
        } else {
            c2(a(1), a(rng.below(1 << 32)))
        }
    };
    if depth == 0 {
        return leaf(rng);
    }
    match rng.below(5) {
        0 | 1 => leaf(rng),
        2 => c2(a(4), random_formula(rng, leaf_count, depth - 1)),
        3 => c3(
            a(5),
            random_formula(rng, leaf_count, depth - 1),
            random_formula(rng, leaf_count, depth - 1),
        ),
        _ => {
            // Condition biased to a loobean-producing equality so the
            // status-0 path gets real coverage.
            let cond = c3(a(5), leaf(rng), leaf(rng));
            c2(
                a(6),
                c3(
                    cond,
                    random_formula(rng, leaf_count, depth - 1),
                    random_formula(rng, leaf_count, depth - 1),
                ),
            )
        }
    }
}

fn random_leaf(rng: &mut SplitMix64) -> u32 {
    match rng.below(6) {
        0 => 0,
        1 => 1,
        2 => u32::MAX,
        3 => u32::MAX - 1,
        _ => u32::try_from(rng.below(1 << 32)).unwrap(),
    }
}

#[test]
fn rv32_random_corpus_never_answers_wrongly() {
    let mut rng = SplitMix64::new(0x5256_3332_4A45_5431); // "RV32JET1"
    let mut sound_cases = 0u32;
    for _ in 0..500 {
        let leaf_count = u32::try_from(rng.below(4)).unwrap() + 1;
        let formula = random_formula(&mut rng, leaf_count, 3);
        let image = lower(&formula, leaf_count).unwrap();
        let leaves: Vec<u32> = (0..leaf_count).map(|_| random_leaf(&mut rng)).collect();
        let exit = execute(&image, &leaves, RV32_MAX_STEPS).unwrap();
        if exit.status == 0 {
            let mut m = Meter::new(10_000_000, 10_000_000);
            let want = eval(1, subject_noun(&leaves), formula.clone(), &mut m).unwrap();
            assert_eq!(want, a(u64::from(exit.value)));
            sound_cases += 1;
        }
    }
    assert!(sound_cases > 150, "only {sound_cases} status-0 cases");
}

#[test]
fn rv32_interpreter_is_closed_and_bounded() {
    // Unknown encoding.
    let bad = Rv32Image {
        words: vec![0xFFFF_FFFF],
        leaf_count: 1,
    };
    assert!(matches!(
        execute(&bad, &[0], 10),
        Err(Rv32Trap::IllegalInstruction { .. })
    ));
    // Infinite loop hits the step bound (JAL x0, 0 == 0x0000006F).
    let spin = Rv32Image {
        words: vec![0x0000_006F],
        leaf_count: 1,
    };
    assert_eq!(execute(&spin, &[0], 10), Err(Rv32Trap::StepBound));
    // Running off the text is a PC trap, not UB.
    let off = Rv32Image {
        words: vec![0x0000_0013], // ADDI x0, x0, 0
        leaf_count: 1,
    };
    assert!(matches!(
        execute(&off, &[0], 10),
        Err(Rv32Trap::PcOutOfRange { .. })
    ));
    // Arity is checked before execution.
    let img = lower(&c2(a(1), a(1)), 2).unwrap();
    assert!(matches!(
        execute(&img, &[1], 10_000),
        Err(Rv32Trap::InputArity {
            expected: 2,
            got: 1
        })
    ));
    // Loads outside [SUBJECT_BASE, STACK_TOP) are range traps:
    // LW t0, 0(x0) reads address 0.
    let oob = Rv32Image {
        words: vec![0x0000_2283], // lw x5, 0(x0)
        leaf_count: 1,
    };
    assert!(matches!(
        execute(&oob, &[0], 10),
        Err(Rv32Trap::AccessOutOfRange { addr: 0 })
    ));
}

#[test]
fn rv32_image_id_binds_text_leafcount_and_abi() {
    assert_eq!(RV32_ABI_VERSION, 1);
    let img = lower(&c2(a(1), a(7)), 1).unwrap();
    let mut other = img.clone();
    other.leaf_count = 2;
    assert_ne!(img.image_id(), other.image_id());
    let mut mutated = img.clone();
    mutated.words[0] ^= 1;
    assert_ne!(img.image_id(), mutated.image_id());
}

#[test]
fn rv32_lowering_rejects_out_of_grammar_formulas() {
    use crate::rv32::LowerError;
    assert_eq!(lower(&a(0), 1), Err(LowerError::FormulaNotACell));
    // Cons composition (head cell) stays on the interpreter.
    assert_eq!(
        lower(&c2(c2(a(1), a(1)), c2(a(1), a(2))), 1),
        Err(LowerError::UnsupportedOpcode)
    );
    // Opcode 3 is not in the frozen grammar.
    assert_eq!(
        lower(&c2(a(3), c2(a(1), a(1))), 1),
        Err(LowerError::UnsupportedOpcode)
    );
    // Axis 3 is not a leaf of a 3-tuple (it is the [l1 l2] subtree).
    assert_eq!(lower(&c2(a(0), a(3)), 3), Err(LowerError::UnsupportedAxis));
    // 5-byte constant.
    let wide = Noun::atom_from_le_bytes(&[1, 1, 1, 1, 1]);
    assert_eq!(lower(&c2(a(1), wide), 1), Err(LowerError::ConstTooWide));
    // Leaf counts.
    assert_eq!(
        lower(&c2(a(1), a(1)), 0),
        Err(LowerError::LeafCountOutOfRange)
    );
    assert_eq!(
        lower(&c2(a(1), a(1)), MAX_LEAVES + 1),
        Err(LowerError::LeafCountOutOfRange)
    );
}

// ---------------------------------------------------------------------------
// Proof dispatch
// ---------------------------------------------------------------------------

fn checker_with(image: &Rv32Image) -> LocalExecutionChecker {
    let mut c = LocalExecutionChecker::new(RV32_MAX_STEPS);
    c.register_image(image.clone());
    c
}

#[test]
fn honest_local_receipt_verifies() {
    let image = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    let checker = checker_with(&image);
    let (request, receipt) = prove_local(&image, &[41], RV32_MAX_STEPS).unwrap();
    assert_eq!(checker.verify(&request, &receipt), Ok(()));
}

#[test]
fn mutated_journal_is_rejected() {
    let image = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    let checker = checker_with(&image);
    let (request, receipt) = prove_local(&image, &[41], RV32_MAX_STEPS).unwrap();
    let mut forged = LocalReceipt::decode(&receipt).unwrap();
    forged.journal.value ^= 1;
    assert_eq!(
        checker.verify(&request, &forged.encode()),
        Err(ProofError::JournalMismatch)
    );
}

#[test]
fn receipt_input_binding_is_exact() {
    let image = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    let checker = checker_with(&image);
    let (request, receipt) = prove_local(&image, &[41], RV32_MAX_STEPS).unwrap();
    let mut forged = LocalReceipt::decode(&receipt).unwrap();
    forged.leaves[0] = 99;
    assert_eq!(
        checker.verify(&request, &forged.encode()),
        Err(ProofError::InputMismatch)
    );
}

#[test]
fn receipt_image_binding_is_exact() {
    let inc = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    let other = lower(&c2(a(1), a(7)), 1).unwrap();
    let checker = checker_with(&inc);
    let (request, _) = prove_local(&inc, &[41], RV32_MAX_STEPS).unwrap();
    // Receipt names a different image than the request.
    let (_, other_receipt) = prove_local(&other, &[41], RV32_MAX_STEPS).unwrap();
    assert_eq!(
        checker.verify(&request, &other_receipt),
        Err(ProofError::ImageIdMismatch)
    );
    // Request/receipt agree on an image the checker never pinned.
    let (other_request, other_receipt) = prove_local(&other, &[41], RV32_MAX_STEPS).unwrap();
    assert_eq!(
        checker.verify(&other_request, &other_receipt),
        Err(ProofError::UnknownImage)
    );
}

#[test]
fn malformed_receipts_are_rejected() {
    let image = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    let checker = checker_with(&image);
    let (request, receipt) = prove_local(&image, &[41], RV32_MAX_STEPS).unwrap();
    // Truncated.
    assert_eq!(
        checker.verify(&request, &receipt[..receipt.len() - 1]),
        Err(ProofError::MalformedReceipt)
    );
    // Trailing garbage.
    let mut long = receipt.clone();
    long.push(0);
    assert_eq!(
        checker.verify(&request, &long),
        Err(ProofError::MalformedReceipt)
    );
    // Wrong version.
    let mut wrong = receipt.clone();
    wrong[0] ^= 1;
    assert_eq!(
        checker.verify(&request, &wrong),
        Err(ProofError::MalformedReceipt)
    );
    // Zero-leaf receipts are outside the ABI.
    let zero = LocalReceipt {
        image_id: image.image_id(),
        leaves: Vec::new(),
        journal: crate::proof::Journal {
            status: 0,
            value: 0,
        },
    };
    assert_eq!(
        checker.verify(&request, &zero.encode()),
        Err(ProofError::MalformedReceipt)
    );
}

#[test]
fn request_commitments_bind_independently() {
    // A verifier given a request for input A must reject a receipt for
    // input B even when that receipt is internally consistent.
    let image = lower(&c2(a(4), c2(a(0), a(1))), 1).unwrap();
    let checker = checker_with(&image);
    let (_, receipt_b) = prove_local(&image, &[7], RV32_MAX_STEPS).unwrap();
    let request_a = ProofRequest {
        image_id: image.image_id(),
        input_commit: input_commit(&[41]),
        journal_commit: crate::proof::Journal {
            status: 0,
            value: 42,
        }
        .commit(),
    };
    assert_eq!(
        checker.verify(&request_a, &receipt_b),
        Err(ProofError::InputMismatch)
    );
}

// ---------------------------------------------------------------------------
// Golden files: byte-exact against the committed fixtures
// ---------------------------------------------------------------------------

#[test]
fn committed_vector_files_are_byte_exact() {
    let base =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors/jet");
    for (name, content) in vectors::vector_files() {
        let committed = std::fs::read(base.join(name))
            .unwrap_or_else(|e| panic!("missing committed vector {name}: {e}"));
        assert_eq!(
            committed,
            content.as_bytes(),
            "committed {name} differs from fresh emission"
        );
    }
}

#[test]
fn vector_json_names_are_unique() {
    for (name, content) in vectors::vector_files() {
        for case_name in content.match_indices("\"name\":\"").map(|(i, _)| {
            let rest = &content[i + 8..];
            &rest[..rest.find('"').unwrap_or(0)]
        }) {
            assert_eq!(
                content
                    .matches(&format!("\"name\":\"{case_name}\""))
                    .count(),
                1,
                "duplicate case {case_name} in {name}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Proof architecture and exact commitment reference mechanics
// ---------------------------------------------------------------------------

fn proof_architecture() -> ProofArchitectureManifest {
    ProofArchitectureManifest {
        numeric_profile: [0x11; 32],
        checkpoint: [0x22; 32],
        activation_commitment: [0x33; 32],
        projection_hook: [0x44; 32],
        moe_route_policy: [0x55; 32],
        tolerance_ppm: 250,
    }
}

#[test]
fn proof_architecture_profile_binds_every_declared_choice() {
    let manifest = proof_architecture();
    let id = manifest.profile_id();
    let mutations = [
        ProofArchitectureManifest {
            numeric_profile: [0x12; 32],
            ..manifest
        },
        ProofArchitectureManifest {
            checkpoint: [0x23; 32],
            ..manifest
        },
        ProofArchitectureManifest {
            activation_commitment: [0x34; 32],
            ..manifest
        },
        ProofArchitectureManifest {
            projection_hook: [0x45; 32],
            ..manifest
        },
        ProofArchitectureManifest {
            moe_route_policy: [0x56; 32],
            ..manifest
        },
        ProofArchitectureManifest {
            tolerance_ppm: 251,
            ..manifest
        },
    ];
    for mutation in mutations {
        assert_ne!(mutation.profile_id(), id);
    }
}

#[test]
fn cpu_commitment_reference_binds_artifact_challenge_profile_and_fused_relation() {
    let artifact = artifact_id(b"canonical tensor bytes");
    let profile_id = proof_architecture().profile_id();
    let challenge = [0x66; 32];
    let trace_root = [0x77; 32];
    let relation = [0x88; 32];
    let mut declaration = CommitmentDeclaration {
        artifact_id: artifact,
        profile_id,
        challenge,
        trace_root,
        fused_relation_id: relation,
        work_commit: work_commit(artifact, profile_id, challenge, trace_root, relation),
    };
    assert_eq!(declaration.validate(), Ok(()));
    declaration.trace_root[0] ^= 1;
    assert_eq!(
        declaration.validate(),
        Err(CommitmentError::WorkCommitMismatch)
    );
    assert_ne!(
        artifact_id(b"canonical tensor bytes"),
        artifact_id(b"canonical tensor bytes\0")
    );
}

// ---------------------------------------------------------------------------
// Feature-gated real RISC Zero backend
// ---------------------------------------------------------------------------

#[cfg(feature = "risc0")]
fn risc0_context() -> crate::risc0::Risc0ProofContext {
    crate::risc0::Risc0ProofContext {
        chain_id: [0x91; 32],
        domain: [0x92; 32],
        profile_id: proof_architecture().profile_id(),
    }
}

#[cfg(feature = "risc0")]
fn certified_inc_risc0_input(
    leaves: &[u32],
) -> (JetRegistry, crate::risc0::Risc0ProofInput, Rv32Image, JetId) {
    let registry = vectors::shipped_registry();
    let id = jet_id(&semantics_hash(&inc_formula()), INC_IMPL_TAG);
    let image = lower(&inc_formula(), 1).unwrap();
    let input = crate::risc0::Risc0ProofInput::certified(
        &registry,
        &id,
        &image,
        leaves,
        risc0_context(),
        RV32_MAX_STEPS,
    )
    .unwrap();
    (registry, input, image, id)
}

#[cfg(feature = "risc0")]
#[test]
fn risc0_builder_rejects_uncertified_jet_and_image_substitution() {
    let registry = vectors::shipped_registry();
    let unknown = JetId([0xED; 32]);
    let image = lower(&inc_formula(), 1).unwrap();
    assert_eq!(
        crate::risc0::Risc0ProofInput::certified(
            &registry,
            &unknown,
            &image,
            &[41],
            risc0_context(),
            RV32_MAX_STEPS,
        ),
        Err(crate::risc0::Risc0Error::UncertifiedJet)
    );
    let inc_id = jet_id(&semantics_hash(&inc_formula()), INC_IMPL_TAG);
    let substitute = lower(&c2(a(1), a(42)), 1).unwrap();
    assert_eq!(
        crate::risc0::Risc0ProofInput::certified(
            &registry,
            &inc_id,
            &substitute,
            &[41],
            risc0_context(),
            RV32_MAX_STEPS,
        ),
        Err(crate::risc0::Risc0Error::ImageSubstitution)
    );
}

#[cfg(feature = "risc0")]
#[test]
fn risc0_guest_execution_matches_host_rv32_and_interpreted_fallback() {
    for leaf in [41, u32::MAX] {
        let (_, input, image, _) = certified_inc_risc0_input(&[leaf]);
        let decoded =
            noos_jet_risc0_shared::ProofInput::decode(&input.canonical_guest_input()).unwrap();
        let guest_claim = decoded.execute().unwrap();
        assert_eq!(&guest_claim, &input.request().claim);
        assert_eq!(guest_claim.leaf_count, 1);
        let host = execute(&image, &[leaf], RV32_MAX_STEPS).unwrap();
        assert_eq!(
            (guest_claim.status, guest_claim.value, guest_claim.steps),
            (host.status, host.value, host.steps)
        );
        let mut meter = Meter::new(1_000_000, 1_000_000);
        let interpreted = eval(1, subject_noun(&[leaf]), inc_formula(), &mut meter).unwrap();
        if guest_claim.status == 0 {
            assert_eq!(interpreted, a(u64::from(guest_claim.value)));
        } else {
            assert_eq!(guest_claim.status, 1);
            assert_eq!(interpreted, a(u64::from(u32::MAX) + 1));
        }
    }
}

#[cfg(feature = "risc0")]
#[test]
fn risc0_verifier_policy_rejects_noncanonical_image_and_arity_substitution() {
    let (registry, input, _, _) = certified_inc_risc0_input(&[41]);
    let verifier = crate::risc0::Risc0Verifier::new(&registry, risc0_context());
    assert_eq!(verifier.validate_request(input.request()), Ok(()));

    let mut image_substitution = input.request().clone();
    image_substitution.claim.rv32_image_id = lower(&c2(a(1), a(42)), 1).unwrap().image_id();
    assert_eq!(
        verifier.validate_request(&image_substitution),
        Err(crate::risc0::Risc0Error::ImageSubstitution)
    );

    for invalid_leaf_count in [0, crate::rv32::MAX_LEAVES + 1] {
        let mut invalid_arity = input.request().clone();
        invalid_arity.claim.leaf_count = invalid_leaf_count;
        assert_eq!(
            verifier.validate_request(&invalid_arity),
            Err(crate::risc0::Risc0Error::InputArity)
        );
    }

    let mut arity_substitution = input.request().clone();
    arity_substitution.claim.leaf_count = 2;
    assert_eq!(
        verifier.validate_request(&arity_substitution),
        Err(crate::risc0::Risc0Error::ImageSubstitution)
    );
}

#[cfg(feature = "risc0")]
#[test]
fn real_risc0_cpu_receipt_verifies_and_all_binding_falsifiers_reject() {
    let (registry, input, _, _) = certified_inc_risc0_input(&[41]);
    let verifier = crate::risc0::Risc0Verifier::new(&registry, risc0_context());
    let (request, receipt) = crate::risc0::prove_risc0_cpu(&input).unwrap();
    assert_eq!(verifier.verify(&request, &receipt), Ok(()));

    let mut tampered_receipt = receipt.clone();
    crate::risc0::tamper_receipt_journal(&mut tampered_receipt);
    assert_eq!(
        verifier.verify(&request, &tampered_receipt),
        Err(crate::risc0::Risc0Error::ReceiptVerification)
    );

    let mut image_substitution = request.clone();
    image_substitution.claim.rv32_image_id = lower(&c2(a(1), a(42)), 1).unwrap().image_id();
    assert_eq!(
        verifier.verify(&image_substitution, &tampered_receipt),
        Err(crate::risc0::Risc0Error::ImageSubstitution)
    );

    let mut arity_substitution = request.clone();
    arity_substitution.claim.leaf_count = 0;
    assert_eq!(
        verifier.verify(&arity_substitution, &tampered_receipt),
        Err(crate::risc0::Risc0Error::InputArity)
    );

    let mut journal_splice = request.clone();
    journal_splice.claim.value ^= 1;
    journal_splice.claim.journal_commit[0] ^= 1;
    assert_eq!(
        verifier.verify(&journal_splice, &receipt),
        Err(crate::risc0::Risc0Error::JournalMismatch)
    );

    let mut wrong_method = request.clone();
    wrong_method.method_id[0] ^= 1;
    assert_eq!(
        verifier.verify(&wrong_method, &receipt),
        Err(crate::risc0::Risc0Error::MethodImageMismatch)
    );

    let mut replay = request.clone();
    replay.claim.context.chain_id[0] ^= 1;
    assert_eq!(
        verifier.verify(&replay, &receipt),
        Err(crate::risc0::Risc0Error::ContextMismatch)
    );

    let mut wrong_domain = request.clone();
    wrong_domain.claim.context.domain[0] ^= 1;
    assert_eq!(
        verifier.verify(&wrong_domain, &receipt),
        Err(crate::risc0::Risc0Error::ContextMismatch)
    );

    let mut wrong_profile = request;
    wrong_profile.claim.context.profile_id[0] ^= 1;
    assert_eq!(
        verifier.verify(&wrong_profile, &receipt),
        Err(crate::risc0::Risc0Error::ContextMismatch)
    );
}

#[cfg(feature = "risc0")]
#[test]
fn real_risc0_recursive_succinct_receipt_verifies() {
    let (registry, input, _, _) = certified_inc_risc0_input(&[41]);
    let verifier = crate::risc0::Risc0Verifier::new(&registry, risc0_context());
    let (request, receipt) = crate::risc0::prove_risc0_succinct_cpu(&input).unwrap();
    assert!(receipt.is_succinct());
    assert_eq!(verifier.verify(&request, &receipt), Ok(()));
}

#[cfg(feature = "risc0")]
#[test]
fn committed_risc0_vector_is_byte_exact() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/jet/jet-risc0-proof-v1.json");
    let committed = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("missing committed vector {}: {error}", path.display()));
    assert_eq!(committed, vectors::risc0_json().as_bytes());
}
