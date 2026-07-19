//! Behavioral tests: header wire law and receipt split, proposal-commitment
//! inclusion/exclusion, DAG insertion/orphans/duplicate window, fork-choice
//! ordering with finality dominance, reorg planning, work saturation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use noos_codec::{CodecError, NoosDecode, NoosEncode};
use noos_ground::{DuplicateSet, GroundTicketV1, U256};

use crate::dag::{DagError, HeaderDag, InsertOutcome, TicketTuple};
use crate::fork::{u256_saturating_add, ForkScore};
use crate::header::{BlockHeaderV1, Bytes96, CheckpointRef, HeaderError, EPOCH_LENGTH, ZERO_ROOT};
use crate::vector_gen::{
    assemble, fixture_chain_id, fixture_ticket, genesis_header, header_fields, minimal_body,
    rich_header,
};
use crate::BlockBodyV1;

// ---------------------------------------------------------------------------
// Header wire law
// ---------------------------------------------------------------------------

#[test]
fn header_roundtrip_is_byte_identical() {
    for h in [rich_header(), genesis_header()] {
        let bytes = h.encode_canonical();
        let back = BlockHeaderV1::decode_canonical(&bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.encode_canonical(), bytes);
    }
}

#[test]
fn header_rejects_truncation_at_every_length() {
    let bytes = rich_header().encode_canonical();
    for cut in 0..bytes.len() {
        let err = BlockHeaderV1::decode_canonical(&bytes[..cut]).unwrap_err();
        assert!(
            matches!(
                err,
                CodecError::Truncated
                    | CodecError::UnknownVersion
                    | CodecError::UnknownMandatoryField
            ),
            "cut at {cut}: {err:?}"
        );
    }
}

#[test]
fn header_rejects_trailing_bytes_and_unknown_version() {
    let h = rich_header();
    let mut trailing = h.encode_canonical();
    trailing.push(0);
    assert_eq!(
        BlockHeaderV1::decode_canonical(&trailing).unwrap_err(),
        CodecError::TrailingBytes
    );
    assert_eq!(
        BlockHeaderV1::decode_canonical(&assemble(7, &header_fields(&h))).unwrap_err(),
        CodecError::UnknownVersion
    );
}

#[test]
fn every_field_tag_is_enforced() {
    let h = rich_header();
    let fields = header_fields(&h);
    assert_eq!(fields.len(), 29);
    for i in 0..fields.len() {
        let mut bad = fields.clone();
        bad[i].0 = 0x7999;
        assert_eq!(
            BlockHeaderV1::decode_canonical(&assemble(1, &bad)).unwrap_err(),
            CodecError::UnknownMandatoryField,
            "field index {i}"
        );
    }
}

#[test]
fn every_field_value_tamper_changes_decode_and_block_hash() {
    let h = rich_header();
    let base_hash = h.block_hash().unwrap();
    let fields = header_fields(&h);
    for i in 0..fields.len() {
        let mut tampered = fields.clone();
        tampered[i].1[0] ^= 0x01;
        let back = BlockHeaderV1::decode_canonical(&assemble(1, &tampered)).unwrap();
        assert_ne!(back, h, "field index {i} tamper not visible");
        assert_ne!(back.block_hash().unwrap(), base_hash, "field index {i}");
    }
}

#[test]
fn receipt_split_tag_confusion_is_a_decode_error() {
    let h = rich_header();
    let fields = header_fields(&h);
    // Field list indices: 8 = execution_receipt_root (tag 9),
    // 15 = lumen_receipts_state_root (tag 16).
    assert_eq!(fields[8].0, 9);
    assert_eq!(fields[15].0, 16);

    // Swap the tags.
    let mut swapped = fields.clone();
    swapped[8].0 = 16;
    swapped[15].0 = 9;
    assert_eq!(
        BlockHeaderV1::decode_canonical(&assemble(1, &swapped)).unwrap_err(),
        CodecError::UnknownMandatoryField
    );

    // Omit the Lumen receipts state root.
    let mut missing = fields.clone();
    missing.remove(15);
    assert_eq!(
        BlockHeaderV1::decode_canonical(&assemble(1, &missing)).unwrap_err(),
        CodecError::UnknownMandatoryField
    );

    // Omit the execution receipt root.
    let mut missing_exec = fields.clone();
    missing_exec.remove(8);
    assert_eq!(
        BlockHeaderV1::decode_canonical(&assemble(1, &missing_exec)).unwrap_err(),
        CodecError::UnknownMandatoryField
    );

    // Present the execution tag twice (one root masquerading as both).
    let mut doubled = fields;
    doubled[15].0 = 9;
    assert_eq!(
        BlockHeaderV1::decode_canonical(&assemble(1, &doubled)).unwrap_err(),
        CodecError::UnknownMandatoryField
    );
}

#[test]
fn structural_validation_rules() {
    let chain = fixture_chain_id();
    let h = rich_header();
    h.validate_structure(&chain, false).unwrap();

    assert_eq!(
        h.validate_structure(&[0xEE; 32], false).unwrap_err(),
        HeaderError::WrongProtocolIdentity
    );

    let mut bad = h.clone();
    bad.ground_profile_id = 2;
    assert_eq!(
        bad.validate_structure(&chain, false).unwrap_err(),
        HeaderError::WrongGroundProfile { got: 2 }
    );

    let mut loom = h.clone();
    loom.loom_credit = 1;
    assert_eq!(
        loom.validate_structure(&chain, false).unwrap_err(),
        HeaderError::LoomCreditDisabled
    );
    let mut loom_root = h.clone();
    loom_root.loom_credit_root = [1; 32];
    assert_eq!(
        loom_root.validate_structure(&chain, false).unwrap_err(),
        HeaderError::LoomCreditDisabled
    );
    // The same values pass when (in a future network version) the lane is on.
    loom.validate_structure(&chain, true).unwrap();

    let mut cp = h;
    cp.justified_checkpoint.epoch = 0;
    assert_eq!(
        cp.validate_structure(&chain, false).unwrap_err(),
        HeaderError::JustifiedBelowFinalized
    );
}

// ---------------------------------------------------------------------------
// Proposal commitment (ch01 §4.2 law)
// ---------------------------------------------------------------------------

/// Mutates header field `idx` (wire order 0..=28) to a fresh value.
fn mutate_field(h: &BlockHeaderV1, idx: usize) -> BlockHeaderV1 {
    let mut m = h.clone();
    match idx {
        0 => m.chain_id[0] ^= 1,
        1 => m.height ^= 1,
        2 => m.slot ^= 1,
        3 => m.timestamp_ms ^= 1,
        4 => m.parent_hash[0] ^= 1,
        5 => m.proposer_key.0[0] ^= 1,
        6 => m.tx_root[0] ^= 1,
        7 => m.witness_root[0] ^= 1,
        8 => m.execution_receipt_root[0] ^= 1,
        9 => m.evidence_root[0] ^= 1,
        10 => m.body_da_root[0] ^= 1,
        11 => m.notes_root[0] ^= 1,
        12 => m.nullifiers_root[0] ^= 1,
        13 => m.accounts_root[0] ^= 1,
        14 => m.objects_root[0] ^= 1,
        15 => m.lumen_receipts_state_root[0] ^= 1,
        16 => m.params_root[0] ^= 1,
        17 => m.justified_checkpoint.checkpoint_hash[0] ^= 1,
        18 => m.finalized_checkpoint.checkpoint_hash[0] ^= 1,
        19 => m.finality_certificate_root[0] ^= 1,
        20 => m.witness_membership_root[0] ^= 1,
        21 => m.ground_profile_id ^= 1,
        22 => m.ground_target[0] ^= 1,
        23 => m.ground_ticket_root[0] ^= 1,
        24 => m.loom_credit_root[0] ^= 1,
        25 => m.loom_credit ^= 1,
        26 => m.gas_used.bytes ^= 1,
        27 => m.base_prices.p_bytes ^= 1,
        28 => m.proposer_signature.0[0] ^= 1,
        _ => panic!("no field {idx}"),
    }
    m
}

#[test]
fn proposal_commitment_inclusion_exclusion_law() {
    let h = rich_header();
    let base = h.proposal_commitment().unwrap();
    // Wire order indices of the excluded fields:
    // 23 = ground_ticket_root, 28 = proposer_signature.
    for idx in 0..29 {
        let mutated = mutate_field(&h, idx).proposal_commitment().unwrap();
        if idx == 23 || idx == 28 {
            assert_eq!(
                mutated, base,
                "excluded field {idx} perturbed the commitment"
            );
        } else {
            assert_ne!(
                mutated, base,
                "included field {idx} did not perturb the commitment"
            );
        }
    }
}

#[test]
fn proposal_commitment_differs_from_block_hash_domain() {
    let h = rich_header();
    // Same header, two registered domains, disjoint coverage: never equal.
    assert_ne!(h.proposal_commitment().unwrap(), h.block_hash().unwrap());
    // But every excluded-field variant still changes the BLOCK hash.
    let mut sig = h.clone();
    sig.proposer_signature = Bytes96([0xAA; 96]);
    assert_ne!(sig.block_hash().unwrap(), h.block_hash().unwrap());
    assert_eq!(
        sig.proposal_commitment().unwrap(),
        h.proposal_commitment().unwrap()
    );
}

// ---------------------------------------------------------------------------
// DAG fixtures
// ---------------------------------------------------------------------------

fn mk_ticket(nonce: u64) -> GroundTicketV1 {
    GroundTicketV1 {
        nonce,
        ..fixture_ticket()
    }
}

/// Child header of `parent_hash` with controllable work (via `target_le`)
/// and checkpoint claims.
fn mk_header(
    parent_hash: [u8; 32],
    height: u64,
    seed: u8,
    target_le: [u8; 32],
    finalized_epoch: u64,
    justified_epoch: u64,
) -> BlockHeaderV1 {
    let mut h = rich_header();
    h.parent_hash = parent_hash;
    h.height = height;
    h.slot = height;
    h.timestamp_ms = 1_760_000_000_000 + height * 6000;
    h.tx_root = [seed; 32];
    h.ground_target = target_le;
    h.finalized_checkpoint = CheckpointRef {
        epoch: finalized_epoch,
        checkpoint_hash: [0xF0; 32],
    };
    h.justified_checkpoint = CheckpointRef {
        epoch: justified_epoch,
        checkpoint_hash: [0xF1; 32],
    };
    h
}

fn hash_of(h: &BlockHeaderV1) -> [u8; 32] {
    *h.block_hash().unwrap().as_bytes()
}

const MODEST: [u8; 32] = {
    let mut t = [0_u8; 32];
    t[31] = 0x0F;
    t
};

fn new_dag() -> (HeaderDag, [u8; 32]) {
    let genesis = genesis_header();
    let ghash = hash_of(&genesis);
    let dag = HeaderDag::new(genesis, &mk_ticket(0), 8).unwrap();
    (dag, ghash)
}

/// Extends the chain by one block; returns the new hash.
fn extend(dag: &mut HeaderDag, parent: [u8; 32], height: u64, seed: u8, nonce: u64) -> [u8; 32] {
    let h = mk_header(parent, height, seed, MODEST, 0, 0);
    let hash = hash_of(&h);
    match dag.insert(h, &mk_ticket(nonce)).unwrap() {
        InsertOutcome::Inserted { .. } => hash,
        other => panic!("expected insert, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// DAG insertion and indices
// ---------------------------------------------------------------------------

#[test]
fn insert_links_heights_slots_and_ancestors() {
    let (mut dag, ghash) = new_dag();
    let a = extend(&mut dag, ghash, 1, 1, 1);
    let b = extend(&mut dag, a, 2, 2, 2);
    assert_eq!(dag.len(), 3);
    assert!(dag.contains(&b));
    assert_eq!(
        dag.hashes_at_height(1).copied().collect::<Vec<_>>(),
        vec![a]
    );
    assert_eq!(dag.hashes_at_slot(2).copied().collect::<Vec<_>>(), vec![b]);
    let chain: Vec<[u8; 32]> = dag.ancestors(&b).map(|s| s.hash).collect();
    assert_eq!(chain, vec![b, a, ghash]);
    assert_eq!(dag.ancestor_at_height(&b, 0).unwrap().hash, ghash);
    assert_eq!(dag.parent_timestamps(&b, 2).len(), 2);
}

#[test]
fn insert_rejects_duplicates_and_bad_linkage() {
    let (mut dag, ghash) = new_dag();
    let h1 = mk_header(ghash, 1, 1, MODEST, 0, 0);
    dag.insert(h1.clone(), &mk_ticket(1)).unwrap();
    assert_eq!(
        dag.insert(h1.clone(), &mk_ticket(1)).unwrap_err(),
        DagError::DuplicateBlock
    );

    let bad_height = mk_header(ghash, 5, 3, MODEST, 0, 0);
    assert_eq!(
        dag.insert(bad_height, &mk_ticket(3)).unwrap_err(),
        DagError::BadHeight {
            got: 5,
            expected: 1
        }
    );

    let h1_hash = hash_of(&h1);
    let mut slot_regress = mk_header(h1_hash, 2, 4, MODEST, 0, 0);
    slot_regress.slot = 0;
    assert_eq!(
        dag.insert(slot_regress, &mk_ticket(4)).unwrap_err(),
        DagError::SlotRegression
    );

    // Checkpoint view must not regress below the parent's claims.
    let up = mk_header(h1_hash, 2, 5, MODEST, 1, 1);
    let up_hash = hash_of(&up);
    dag.insert(up, &mk_ticket(5)).unwrap();
    let regress = mk_header(up_hash, 3, 6, MODEST, 0, 0);
    assert_eq!(
        dag.insert(regress, &mk_ticket(6)).unwrap_err(),
        DagError::CheckpointRegression
    );

    // Ticket profile must agree with the header.
    let mut wrong_profile_ticket = mk_ticket(7);
    wrong_profile_ticket.profile_id = 2;
    let child = mk_header(h1_hash, 2, 7, MODEST, 0, 0);
    assert_eq!(
        dag.insert(child, &wrong_profile_ticket).unwrap_err(),
        DagError::TicketProfileMismatch
    );
}

// ---------------------------------------------------------------------------
// Orphan pool
// ---------------------------------------------------------------------------

#[test]
fn orphans_require_explicit_contextual_promotion() {
    let (mut dag, ghash) = new_dag();
    let parent = mk_header(ghash, 1, 1, MODEST, 0, 0);
    let parent_hash = hash_of(&parent);
    let child = mk_header(parent_hash, 2, 2, MODEST, 0, 0);
    let child_hash = hash_of(&child);
    let grandchild = mk_header(child_hash, 3, 3, MODEST, 0, 0);
    let grandchild_hash = hash_of(&grandchild);

    // Children arrive before the parent: pooled.
    assert_eq!(
        dag.insert(child, &mk_ticket(2)).unwrap(),
        InsertOutcome::Orphaned {
            hash: child_hash,
            retained: true
        }
    );
    assert_eq!(
        dag.insert(grandchild, &mk_ticket(3)).unwrap(),
        InsertOutcome::Orphaned {
            hash: grandchild_hash,
            retained: true
        }
    );
    assert_eq!(dag.orphan_count(), 2);

    // The linkage layer connects only the parent. Consensus must explicitly
    // take and fully validate each newly reachable orphan.
    let outcome = dag.insert(parent, &mk_ticket(1)).unwrap();
    assert_eq!(outcome, InsertOutcome::Inserted { hash: parent_hash });
    let children = dag.take_orphans_waiting_on(&parent_hash);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].hash, child_hash);
    dag.insert(children[0].header.clone(), &children[0].ticket)
        .unwrap();
    let grandchildren = dag.take_orphans_waiting_on(&child_hash);
    assert_eq!(grandchildren.len(), 1);
    assert_eq!(grandchildren[0].hash, grandchild_hash);
    dag.insert(grandchildren[0].header.clone(), &grandchildren[0].ticket)
        .unwrap();
    assert_eq!(dag.orphan_count(), 0);
    assert!(dag.contains(&grandchild_hash));
}

#[test]
fn orphan_pool_is_bounded_with_deterministic_eviction() {
    let genesis = genesis_header();
    let mut dag = HeaderDag::new(genesis, &mk_ticket(0), 2).unwrap();

    // Three orphans with unknown parents.
    let mut hashes = Vec::new();
    for seed in 1..=3_u8 {
        let orphan = mk_header([0xE0 + seed; 32], 9, seed, MODEST, 0, 0);
        hashes.push(hash_of(&orphan));
        dag.insert(orphan, &mk_ticket(u64::from(seed))).unwrap();
    }
    assert_eq!(dag.orphan_count(), 2);

    // The evictee is exactly the numerically largest hash: re-inserting a
    // pooled orphan is DuplicateBlock, the evicted one pools again.
    let mut sorted = hashes.clone();
    sorted.sort_unstable();
    let evicted = sorted[2];
    for (i, hash) in hashes.iter().enumerate() {
        // Rebuild the exact original orphan for a byte-identical re-insert.
        let orphan = mk_header([0xE0 + (i + 1) as u8; 32], 9, (i + 1) as u8, MODEST, 0, 0);
        let result = dag.insert(orphan, &mk_ticket((i + 1) as u64));
        if *hash == evicted {
            assert_eq!(
                result.unwrap(),
                InsertOutcome::Orphaned {
                    hash: evicted,
                    retained: false
                },
                "evicted orphan must be poolable again (but pool is full of smaller hashes)"
            );
        } else {
            assert_eq!(result.unwrap_err(), DagError::DuplicateBlock);
        }
    }
}

// ---------------------------------------------------------------------------
// Duplicate ticket tuple (ch01 §4.2 rule 8)
// ---------------------------------------------------------------------------

#[test]
fn duplicate_ticket_tuple_rejected_and_window_resets_at_finality() {
    let (mut dag, ghash) = new_dag();
    let mut tip = ghash;
    for height in 1..=EPOCH_LENGTH {
        tip = extend(&mut dag, tip, height, (height % 251) as u8, height);
    }

    // Reusing nonce 10 (used at height 10) above an UNfinalized checkpoint:
    // rejected — the whole path back to genesis is in scope.
    let dup = mk_header(tip, 257, 0xAA, MODEST, 0, 0);
    assert_eq!(
        dag.insert(dup.clone(), &mk_ticket(10)).unwrap_err(),
        DagError::DuplicateTicketTuple
    );

    // The DuplicateSet adapter sees the same window.
    let ticket = mk_ticket(10);
    let scan = dag.duplicate_scan(&tip);
    let proposer = rich_header().proposer_key.0;
    assert!(scan.contains(&proposer, 10, &ticket.extra_nonce));
    assert!(!scan.contains(&proposer, 0xDEAD_BEEF, &ticket.extra_nonce));

    // Finalize epoch 1 at height 256: the window resets there.
    dag.set_finalized(CheckpointRef {
        epoch: 1,
        checkpoint_hash: tip,
    })
    .unwrap();
    assert_eq!(dag.finalized().epoch, 1);
    match dag.insert(dup, &mk_ticket(10)).unwrap() {
        InsertOutcome::Inserted { .. } => {}
        other => panic!("tuple reuse above the finalized checkpoint must connect: {other:?}"),
    }
    let scan = dag.duplicate_scan(&tip);
    assert!(!scan.contains(&proposer, 10, &ticket.extra_nonce));
}

// ---------------------------------------------------------------------------
// Fork choice
// ---------------------------------------------------------------------------

#[test]
fn fork_score_ordering_is_exactly_lexicographic() {
    let lo = [1_u8; 32];
    let hi = [2_u8; 32];
    let s = |f, j, w: u64, h| ForkScore {
        finalized_epoch: f,
        justified_epoch: j,
        work_since_finalized: U256::from_u64(w),
        block_hash: h,
    };
    // Finalized epoch dominates everything.
    assert!(s(1, 1, 0, hi) > s(0, 9, u64::MAX, lo));
    // Justified epoch dominates work.
    assert!(s(1, 2, 0, hi) > s(1, 1, u64::MAX, lo));
    // Work dominates the hash tiebreak.
    assert!(s(1, 1, 2, hi) > s(1, 1, 1, lo));
    // Full tie: the SMALLER hash ranks higher (inverse lexicographic).
    assert!(s(1, 1, 1, lo) > s(1, 1, 1, hi));
    // Equality only for identical tuples.
    assert_eq!(s(1, 1, 1, lo), s(1, 1, 1, lo));
}

#[test]
fn raw_checkpoint_claims_never_increase_fork_weight() {
    let (mut dag, ghash) = new_dag();

    // Branch A claims finalized epoch 1 with negligible work.
    let a1 = mk_header(ghash, 1, 1, [0xFF; 32], 1, 1); // G = 0
    let a1_hash = hash_of(&a1);
    dag.insert(a1, &mk_ticket(1)).unwrap();

    // Branch B carries astronomical work (target 0 => G = 2^256 - 1 each,
    // saturating) but claims the older finalized checkpoint.
    let b1 = mk_header(ghash, 1, 2, [0x00; 32], 0, 0);
    let b1_hash = hash_of(&b1);
    dag.insert(b1, &mk_ticket(2)).unwrap();
    let b2 = mk_header(b1_hash, 2, 3, [0x00; 32], 0, 0);
    let b2_hash = hash_of(&b2);
    dag.insert(b2, &mk_ticket(3)).unwrap();

    let score_b = dag.fork_score(&b2_hash).unwrap();
    assert_eq!(score_b.work_since_finalized, U256::MAX, "saturated");
    let score_a = dag.fork_score(&a1_hash).unwrap();
    assert_eq!(score_a.work_since_finalized, U256::ZERO);

    assert_eq!(score_a.finalized_epoch, 0);
    assert_eq!(score_a.justified_epoch, 0);
    assert_eq!(score_b.finalized_epoch, 0);
    assert_eq!(score_b.justified_epoch, 0);
    assert!(
        score_b > score_a,
        "only verified finality and work are scored"
    );
    assert_eq!(dag.select_head(), Some(b2_hash));
}

#[test]
fn verified_justification_weights_only_its_descendant_branch() {
    let (mut dag, genesis) = new_dag();
    let mut justified_tip = genesis;
    let mut work_tip = genesis;
    for height in 1..=EPOCH_LENGTH {
        let seed = height.to_le_bytes()[0];
        let justified = mk_header(justified_tip, height, seed, MODEST, 0, 0);
        justified_tip = hash_of(&justified);
        dag.insert(justified, &mk_ticket(height)).unwrap();

        let work = mk_header(work_tip, height, seed.wrapping_add(1), [0; 32], 0, 0);
        work_tip = hash_of(&work);
        dag.insert(work, &mk_ticket(height)).unwrap();
    }
    dag.set_justified(CheckpointRef {
        epoch: 1,
        checkpoint_hash: justified_tip,
    })
    .unwrap();

    let justified_score = dag.fork_score(&justified_tip).unwrap();
    let work_score = dag.fork_score(&work_tip).unwrap();
    assert_eq!(justified_score.justified_epoch, 1);
    assert_eq!(work_score.justified_epoch, 0);
    assert_eq!(work_score.work_since_finalized, U256::MAX);
    assert!(justified_score > work_score);
    assert_eq!(dag.select_head(), Some(justified_tip));
}

#[test]
fn work_and_hash_tiebreak_decide_below_equal_checkpoints() {
    let (mut dag, ghash) = new_dag();

    // Heavier single block beats two light blocks.
    let heavy = mk_header(
        ghash,
        1,
        1,
        {
            let mut t = [0_u8; 32];
            t[0] = 0x03; // tiny LE target => huge G
            t
        },
        0,
        0,
    );
    let heavy_hash = hash_of(&heavy);
    dag.insert(heavy, &mk_ticket(1)).unwrap();

    let light1 = mk_header(ghash, 1, 2, [0xFF; 32], 0, 0);
    let light1_hash = hash_of(&light1);
    dag.insert(light1, &mk_ticket(2)).unwrap();
    let light2 = mk_header(light1_hash, 2, 3, [0xFF; 32], 0, 0);
    dag.insert(light2, &mk_ticket(3)).unwrap();

    assert_eq!(dag.select_head(), Some(heavy_hash));

    // Equal-work siblings: the numerically smaller hash wins.
    let (mut dag2, ghash2) = new_dag();
    let c1 = mk_header(ghash2, 1, 10, MODEST, 0, 0);
    let c2 = mk_header(ghash2, 1, 11, MODEST, 0, 0);
    let (h1, h2) = (hash_of(&c1), hash_of(&c2));
    dag2.insert(c1, &mk_ticket(1)).unwrap();
    dag2.insert(c2, &mk_ticket(2)).unwrap();
    assert_eq!(dag2.select_head(), Some(h1.min(h2)));
}

#[test]
fn u256_work_accumulation_saturates() {
    assert_eq!(u256_saturating_add(&U256::MAX, &U256::ONE), U256::MAX);
    assert_eq!(u256_saturating_add(&U256::MAX, &U256::MAX), U256::MAX);
    assert_eq!(
        u256_saturating_add(&U256::from_u64(2), &U256::from_u64(3)),
        U256::from_u64(5)
    );
    // Carry propagation across limbs.
    let almost = U256::from_limbs([u64::MAX, u64::MAX, 0, 0]);
    assert_eq!(
        u256_saturating_add(&almost, &U256::ONE),
        U256::from_limbs([0, 0, 1, 0])
    );
}

// ---------------------------------------------------------------------------
// Reorg planning
// ---------------------------------------------------------------------------

#[test]
fn reorg_plans_are_deterministic_and_exact() {
    let (mut dag, ghash) = new_dag();
    let a1 = extend(&mut dag, ghash, 1, 1, 1);
    let a2 = extend(&mut dag, a1, 2, 2, 2);
    let b1 = extend(&mut dag, ghash, 1, 3, 3);
    let b2 = extend(&mut dag, b1, 2, 4, 4);
    let b3 = extend(&mut dag, b2, 3, 5, 5);

    let plan = dag.plan_reorg(&a2, &b3).unwrap();
    assert_eq!(plan.common_ancestor, ghash);
    assert_eq!(plan.disconnect, vec![a2, a1], "newest first");
    assert_eq!(plan.connect, vec![b1, b2, b3], "oldest first");
    // Determinism: identical plans on repeated calls.
    assert_eq!(dag.plan_reorg(&a2, &b3).unwrap(), plan);
    // Inverse reorg mirrors the plan.
    let back = dag.plan_reorg(&b3, &a2).unwrap();
    assert_eq!(back.disconnect, vec![b3, b2, b1]);
    assert_eq!(back.connect, vec![a1, a2]);
    // Self-reorg is empty.
    let noop = dag.plan_reorg(&b3, &b3).unwrap();
    assert!(noop.disconnect.is_empty() && noop.connect.is_empty());
    // Unknown endpoint.
    assert_eq!(
        dag.plan_reorg(&[9; 32], &b3).unwrap_err(),
        DagError::UnknownBlock
    );
}

#[test]
fn reorgs_never_cross_the_finalized_checkpoint() {
    let (mut dag, ghash) = new_dag();
    // Two competing epoch-length branches.
    let mut tip_a = ghash;
    for height in 1..=EPOCH_LENGTH {
        tip_a = extend(&mut dag, tip_a, height, (height % 251) as u8, height);
    }
    let mut tip_b = ghash;
    for height in 1..=EPOCH_LENGTH {
        tip_b = extend(&mut dag, tip_b, height, 0xB0, 10_000 + height);
    }
    assert_ne!(tip_a, tip_b);

    // Reorg between the branches is fine before finality...
    dag.plan_reorg(&tip_a, &tip_b).unwrap();

    // ...but once epoch 1 finalizes on branch A, crossing it is prohibited.
    dag.set_finalized(CheckpointRef {
        epoch: 1,
        checkpoint_hash: tip_a,
    })
    .unwrap();
    assert_eq!(
        dag.plan_reorg(&tip_a, &tip_b).unwrap_err(),
        DagError::ReorgAcrossFinality
    );

    // New blocks extending the losing branch now conflict with finality.
    let stray = mk_header(tip_b, 257, 0xCC, MODEST, 0, 0);
    assert_eq!(
        dag.insert(stray, &mk_ticket(77_777)).unwrap_err(),
        DagError::ConflictsWithFinality
    );
    // And the losing branch is no longer an eligible tip.
    assert_eq!(dag.tips(), vec![tip_a]);
}

// ---------------------------------------------------------------------------
// Checkpoint state machine
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_advancement_rules() {
    let (mut dag, ghash) = new_dag();
    let mut tip = ghash;
    for height in 1..=EPOCH_LENGTH {
        tip = extend(&mut dag, tip, height, (height % 251) as u8, height);
    }

    // Not a checkpoint height.
    let mid = dag.ancestor_at_height(&tip, 100).unwrap().hash;
    assert_eq!(
        dag.set_finalized(CheckpointRef {
            epoch: 1,
            checkpoint_hash: mid
        })
        .unwrap_err(),
        DagError::NotACheckpointHeight
    );
    // Unknown block.
    assert_eq!(
        dag.set_finalized(CheckpointRef {
            epoch: 1,
            checkpoint_hash: [9; 32]
        })
        .unwrap_err(),
        DagError::UnknownBlock
    );

    dag.set_justified(CheckpointRef {
        epoch: 1,
        checkpoint_hash: tip,
    })
    .unwrap();
    dag.set_finalized(CheckpointRef {
        epoch: 1,
        checkpoint_hash: tip,
    })
    .unwrap();
    assert_eq!(dag.justified().epoch, 1);

    // Finality never regresses.
    assert_eq!(
        dag.set_finalized(CheckpointRef {
            epoch: 0,
            checkpoint_hash: ghash
        })
        .unwrap_err(),
        DagError::FinalityRegression
    );
    assert_eq!(
        dag.set_justified(CheckpointRef {
            epoch: 0,
            checkpoint_hash: ghash
        })
        .unwrap_err(),
        DagError::FinalityRegression
    );
}

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

#[test]
fn body_roundtrip_and_loom_hard_zero() {
    let body = minimal_body();
    let bytes = body.encode_canonical();
    assert_eq!(
        body.encode_canonical_with_ground_ticket(body.ground_ticket.0),
        bytes,
        "ticket substitution encoder must preserve the canonical body wire law"
    );
    let back = BlockBodyV1::decode_canonical(&bytes).unwrap();
    assert_eq!(back, body);
    assert_eq!(back.ground_ticket.0.nonce, fixture_ticket().nonce);

    // The loom claims list is decode-bounded at zero elements: patch the
    // count (second-to-last field's u32 length prefix) to 1.
    let mut smuggled = bytes.clone();
    let idx = bytes.len() - (2 + 4) - 4;
    smuggled[idx] = 1;
    assert_eq!(
        BlockBodyV1::decode_canonical(&smuggled).unwrap_err(),
        CodecError::LengthExceedsBound
    );
}

#[test]
fn ticket_tuple_ordering_is_deterministic() {
    let a = TicketTuple {
        proposer_pubkey: [1; 48],
        nonce: 1,
        extra_nonce: [0; 32],
    };
    let b = TicketTuple {
        proposer_pubkey: [1; 48],
        nonce: 2,
        extra_nonce: [0; 32],
    };
    assert!(a < b);
    assert_eq!(a, a);
}

#[test]
fn checkpoint_expected_height() {
    assert_eq!(
        CheckpointRef {
            epoch: 0,
            checkpoint_hash: ZERO_ROOT
        }
        .expected_height(),
        Some(0)
    );
    assert_eq!(
        CheckpointRef {
            epoch: 3,
            checkpoint_hash: ZERO_ROOT
        }
        .expected_height(),
        Some(3 * EPOCH_LENGTH)
    );
}
