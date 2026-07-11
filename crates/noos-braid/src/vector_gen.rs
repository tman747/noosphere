//! Deterministic conformance-vector construction for
//! `protocol/vectors/braid/`.
//!
//! Shared by `bin/gen_vectors.rs` (writes the JSON files) and the crate
//! tests (which re-derive and verify every case), so the emitted vectors can
//! never drift from the implementation. JSON is emitted by hand from fully
//! controlled ASCII content; the file shape satisfies
//! `tools/gates/check_vectors.py`.
//!
//! Case-byte layouts, per schema:
//!
//! - `noos-braid/header-v1`: bytes are a canonical `BlockHeaderV1` encoding.
//!   Positive: decode then re-encode must be byte-identical, and the
//!   `block_hash` / `proposal_commitment` extras must recompute. Negative:
//!   decode must fail with `error_class`.
//! - `noos-braid/header-validation-v1`: bytes decode as a header; the case
//!   carries the expected `chain_id`. Positive:
//!   `validate_structure(chain_id, false)` passes. Negative: it fails with
//!   `error_class`.
//! - `noos-braid/proposal-commitment-v1`: bytes are a canonical header; the
//!   case carries a claimed `proposal_commitment`. Positive: recomputation
//!   under `NOOS/BLOCK/PROPOSAL/V1` matches. Negative: it must NOT match
//!   (the claim was derived with a wrong inclusion set or wrong domain).
//! - `noos-braid/fork-choice-v1`: bytes are `score_a || score_b`, each score
//!   80 bytes: `finalized_epoch u64 LE || justified_epoch u64 LE ||
//!   work 32 B LE || block_hash 32 B`. The `expected` extra names the winner
//!   (`"a"` or `"b"`) under the plan §6.4 lexicographic law with the
//!   inverse-hash tiebreak (lower hash wins).
//! - `noos-braid/body-v1`: bytes are a canonical `BlockBodyV1` encoding.
//!   Positive: roundtrip. Negative: decode fails with `error_class`
//!   (including any nonzero `loom_credit_claims` count, which is
//!   `length_exceeds_bound` while the lane is disabled).

// Generator/test-support code, never a consensus path: byte construction
// here operates on fully controlled fixture buffers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_codec::{CodecError, NoosEncode, Writer};
use noos_ground::GroundTicketV1;
use noos_lumen::objects::{BoundedBytes, BoundedList, OptionalHash32, OptionalObject};

use crate::body::{BlobDescriptorV1, BlockBodyV1, FinalityCertificateV1, GroundTicketWire};
use crate::fork::ForkScore;
use crate::header::{
    BlockHeaderV1, Bytes48, Bytes96, CheckpointRef, HeaderError, ResourcePriceVectorV1,
    ResourceVectorV1,
};
use noos_ground::U256;

/// One conformance case.
pub struct Case {
    pub name: String,
    pub kind: &'static str,
    pub bytes: Vec<u8>,
    /// Extra `"field": "hex"` pairs (all values hex-encoded byte strings).
    pub extras: Vec<(&'static str, Vec<u8>)>,
    /// Extra `"field": "literal"` string pairs (e.g. fork-choice winner).
    pub extras_str: Vec<(&'static str, String)>,
    pub error_class: Option<&'static str>,
    pub note: String,
}

pub struct VectorFile {
    pub schema: &'static str,
    pub cases: Vec<Case>,
}

fn case(name: &str, kind: &'static str, bytes: Vec<u8>, note: &str) -> Case {
    Case {
        name: name.to_string(),
        kind,
        bytes,
        extras: Vec::new(),
        extras_str: Vec::new(),
        error_class: None,
        note: note.to_string(),
    }
}

fn positive(name: &str, bytes: Vec<u8>, note: &str) -> Case {
    case(name, "positive", bytes, note)
}

fn negative(name: &str, bytes: Vec<u8>, err: CodecError, note: &str) -> Case {
    let mut c = case(name, "negative", bytes, note);
    c.error_class = Some(err.class_name());
    c
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn h(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// The devnet-fixture chain id used by every braid vector.
pub fn fixture_chain_id() -> [u8; 32] {
    h(0xC1)
}

/// A fully populated, structurally valid header fixture.
pub fn rich_header() -> BlockHeaderV1 {
    BlockHeaderV1 {
        chain_id: fixture_chain_id(),
        height: 513,
        slot: 520,
        timestamp_ms: 1_760_000_003_120,
        parent_hash: h(0x05),
        proposer_key: Bytes48([0x06; 48]),
        tx_root: h(0x07),
        witness_root: h(0x08),
        execution_receipt_root: h(0x09),
        evidence_root: h(0x0A),
        body_da_root: h(0x0B),
        notes_root: h(0x0C),
        nullifiers_root: h(0x0D),
        accounts_root: h(0x0E),
        objects_root: h(0x0F),
        lumen_receipts_state_root: h(0x10),
        params_root: h(0x11),
        justified_checkpoint: CheckpointRef {
            epoch: 2,
            checkpoint_hash: h(0x12),
        },
        finalized_checkpoint: CheckpointRef {
            epoch: 1,
            checkpoint_hash: h(0x13),
        },
        finality_certificate_root: h(0x14),
        witness_membership_root: h(0x15),
        ground_profile_id: 1,
        ground_target: {
            let mut t = [0_u8; 32];
            t[31] = 0x0F; // high LE target => modest work
            t
        },
        ground_ticket_root: h(0x18),
        loom_credit_root: [0_u8; 32],
        loom_credit: 0,
        gas_used: ResourceVectorV1 {
            bytes: 4096,
            grain_steps: 100_000,
            proof_units: 7,
            state_word_epochs: 512,
            blob_bytes: 65_536,
        },
        base_prices: ResourcePriceVectorV1 {
            p_bytes: 1,
            p_grain_steps: 2,
            p_proof_units: 3,
            p_state_word_epochs: 4,
            p_blob_bytes: 5,
        },
        proposer_signature: Bytes96([0x1D; 96]),
    }
}

/// A genesis-shaped header fixture (height 0, zero parent, zero roots).
pub fn genesis_header() -> BlockHeaderV1 {
    let mut g = rich_header();
    g.height = 0;
    g.slot = 0;
    g.timestamp_ms = 1_760_000_000_000;
    g.parent_hash = [0_u8; 32];
    g.justified_checkpoint = CheckpointRef::default();
    g.finalized_checkpoint = CheckpointRef::default();
    g.ground_target = [0xFF_u8; 32];
    g
}

fn enc<T: NoosEncode>(v: &T) -> Vec<u8> {
    let mut w = Writer::new();
    v.encode(&mut w);
    w.into_bytes()
}

/// The header's 29 `(tag, canonical value bytes)` pairs in wire order.
pub fn header_fields(hd: &BlockHeaderV1) -> Vec<(u16, Vec<u8>)> {
    vec![
        (1, enc(&hd.chain_id)),
        (2, enc(&hd.height)),
        (3, enc(&hd.slot)),
        (4, enc(&hd.timestamp_ms)),
        (5, enc(&hd.parent_hash)),
        (6, enc(&hd.proposer_key)),
        (7, enc(&hd.tx_root)),
        (8, enc(&hd.witness_root)),
        (9, enc(&hd.execution_receipt_root)),
        (10, enc(&hd.evidence_root)),
        (11, enc(&hd.body_da_root)),
        (12, enc(&hd.notes_root)),
        (13, enc(&hd.nullifiers_root)),
        (14, enc(&hd.accounts_root)),
        (15, enc(&hd.objects_root)),
        (16, enc(&hd.lumen_receipts_state_root)),
        (17, enc(&hd.params_root)),
        (18, enc(&hd.justified_checkpoint)),
        (19, enc(&hd.finalized_checkpoint)),
        (20, enc(&hd.finality_certificate_root)),
        (21, enc(&hd.witness_membership_root)),
        (22, enc(&hd.ground_profile_id)),
        (23, enc(&hd.ground_target)),
        (24, enc(&hd.ground_ticket_root)),
        (25, enc(&hd.loom_credit_root)),
        (26, enc(&hd.loom_credit)),
        (27, enc(&hd.gas_used)),
        (28, enc(&hd.base_prices)),
        (29, enc(&hd.proposer_signature)),
    ]
}

/// Assembles header bytes from an explicit version + field list (for
/// tag-swap / omission negatives).
pub fn assemble(version: u16, fields: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(version);
    for (tag, value) in fields {
        w.put_u16(*tag);
        w.put_raw(value);
    }
    w.into_bytes()
}

/// Ticket fixture for body vectors.
pub fn fixture_ticket() -> GroundTicketV1 {
    GroundTicketV1 {
        profile_id: 1,
        nonce: 0x0123_4567_89AB_CDEF,
        extra_nonce: [0x2E; 32],
        digest: noos_crypto::Hash32::from_bytes(h(0x2F)),
    }
}

fn fixture_certificate() -> FinalityCertificateV1 {
    FinalityCertificateV1 {
        source: CheckpointRef {
            epoch: 1,
            checkpoint_hash: h(0x31),
        },
        target: CheckpointRef {
            epoch: 2,
            checkpoint_hash: h(0x32),
        },
        participation_bitmap: BoundedBytes::new(vec![0xFF; 32]).unwrap(),
        aggregate_signature: Bytes96([0x33; 96]),
        raw_weight_sum: 700_000_000,
        effective_weight_sum: 650_000_000,
        membership_root: h(0x34),
    }
}

fn fixture_blob() -> BlobDescriptorV1 {
    BlobDescriptorV1 {
        namespace: 1,
        content_root: h(0x41),
        original_bytes: 900_000,
        shard_bytes: 65_536,
        data_shards: 16,
        parity_shards: 16,
        retention_epochs: 8,
        codec_id: 1,
        encryption_descriptor: OptionalObject(None),
        access_policy_root: OptionalHash32(Some(h(0x42))),
    }
}

/// A minimal valid body (empty collections + the mandatory ticket).
pub fn minimal_body() -> BlockBodyV1 {
    BlockBodyV1 {
        transactions: BoundedList::new(Vec::new()).unwrap(),
        segregated_witnesses: BoundedList::new(Vec::new()).unwrap(),
        system_transitions: BoundedList::new(Vec::new()).unwrap(),
        finality_certificates: BoundedList::new(Vec::new()).unwrap(),
        ground_ticket: GroundTicketWire(fixture_ticket()),
        loom_credit_claims: BoundedList::new(Vec::new()).unwrap(),
        consensus_blob_descriptors: BoundedList::new(Vec::new()).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

fn header_file() -> VectorFile {
    let rich = rich_header();
    let genesis = genesis_header();
    let mut cases = Vec::new();

    for (name, hd, note) in [
        (
            "header-rich",
            &rich,
            "fully populated valid header; roundtrip + hash laws",
        ),
        (
            "header-genesis-shape",
            &genesis,
            "height-0 header with zero parent and checkpoints",
        ),
    ] {
        let mut c = positive(name, hd.encode_canonical(), note);
        c.extras
            .push(("block_hash", hd.block_hash().unwrap().as_bytes().to_vec()));
        c.extras.push((
            "proposal_commitment",
            hd.proposal_commitment().unwrap().as_bytes().to_vec(),
        ));
        cases.push(c);
    }

    let canon = rich.encode_canonical();

    let mut truncated = canon.clone();
    truncated.truncate(canon.len() - 10);
    cases.push(negative(
        "header-truncated",
        truncated,
        CodecError::Truncated,
        "last 10 bytes removed",
    ));

    let mut trailing = canon.clone();
    trailing.push(0x00);
    cases.push(negative(
        "header-trailing-byte",
        trailing,
        CodecError::TrailingBytes,
        "one byte appended after the canonical encoding",
    ));

    let fields = header_fields(&rich);
    cases.push(negative(
        "header-unknown-version",
        assemble(2, &fields),
        CodecError::UnknownVersion,
        "version 2 is not decodable by the v1 law",
    ));

    // Receipt split: swapping the two receipt-field TAGS is a decode error.
    let mut swapped = fields.clone();
    swapped[8].0 = 16; // execution_receipt_root position carries tag 16
    swapped[15].0 = 9; // lumen_receipts_state_root position carries tag 9
    cases.push(negative(
        "header-receipt-tags-swapped",
        assemble(1, &swapped),
        CodecError::UnknownMandatoryField,
        "tags 9/16 interchanged: the receipt split is decode-enforced",
    ));

    // Receipt split: omitting lumen_receipts_state_root entirely.
    let mut missing = fields.clone();
    missing.remove(15);
    cases.push(negative(
        "header-missing-lumen-receipts-root",
        assemble(1, &missing),
        CodecError::UnknownMandatoryField,
        "field 16 omitted: both receipt fields are mandatory",
    ));

    // Receipt split: execution_receipt_root presented twice.
    let mut doubled = fields.clone();
    doubled[15].0 = 9;
    cases.push(negative(
        "header-doubled-execution-receipt-tag",
        assemble(1, &doubled),
        CodecError::UnknownMandatoryField,
        "tag 9 where tag 16 must appear",
    ));

    let mut bad_first = fields;
    bad_first[0].0 = 0x0100;
    cases.push(negative(
        "header-unknown-first-tag",
        assemble(1, &bad_first),
        CodecError::UnknownMandatoryField,
        "unknown mandatory tag in the first position",
    ));

    VectorFile {
        schema: "noos-braid/header-v1",
        cases,
    }
}

fn validation_file() -> VectorFile {
    let chain = fixture_chain_id();
    let base = rich_header();
    let mut cases = Vec::new();

    let mut ok = positive(
        "valid-structure",
        base.encode_canonical(),
        "chain id matches, profile 1, loom zero, justified >= finalized",
    );
    ok.extras.push(("chain_id", chain.to_vec()));
    cases.push(ok);

    let mut wrong_chain = positive(
        "wrong-chain-id",
        base.encode_canonical(),
        "validated against a different chain id: wrong_protocol_identity",
    );
    wrong_chain.kind = "negative";
    wrong_chain.extras.push(("chain_id", h(0xEE).to_vec()));
    wrong_chain.error_class = Some(HeaderError::WrongProtocolIdentity.class_name());
    cases.push(wrong_chain);

    let mut v = base.clone();
    v.ground_profile_id = 2;
    let mut c = negative_validation(
        "wrong-ground-profile",
        &v,
        &chain,
        HeaderError::WrongGroundProfile { got: 2 },
    );
    c.note = "ground_profile_id must be 1 under Braid v1".to_string();
    cases.push(c);

    let mut v = base.clone();
    v.loom_credit = 1;
    cases.push(negative_validation(
        "loom-credit-nonzero",
        &v,
        &chain,
        HeaderError::LoomCreditDisabled,
    ));

    let mut v = base.clone();
    v.loom_credit_root = h(0x77);
    cases.push(negative_validation(
        "loom-credit-root-nonzero",
        &v,
        &chain,
        HeaderError::LoomCreditDisabled,
    ));

    let mut v = base;
    v.justified_checkpoint.epoch = 0;
    cases.push(negative_validation(
        "justified-below-finalized",
        &v,
        &chain,
        HeaderError::JustifiedBelowFinalized,
    ));

    VectorFile {
        schema: "noos-braid/header-validation-v1",
        cases,
    }
}

fn negative_validation(name: &str, hd: &BlockHeaderV1, chain: &[u8; 32], err: HeaderError) -> Case {
    let mut c = case(name, "negative", hd.encode_canonical(), "");
    c.extras.push(("chain_id", chain.to_vec()));
    c.error_class = Some(err.class_name());
    c
}

fn commitment_file() -> VectorFile {
    let base = rich_header();
    let base_commit = base.proposal_commitment().unwrap();
    let mut cases = Vec::new();

    let mut c = positive(
        "commitment-base",
        base.encode_canonical(),
        "commitment over every field except tags 24 and 29",
    );
    c.extras
        .push(("proposal_commitment", base_commit.as_bytes().to_vec()));
    cases.push(c);

    let mut ticket_var = base.clone();
    ticket_var.ground_ticket_root = h(0x99);
    let mut c = positive(
        "commitment-excludes-ground-ticket-root",
        ticket_var.encode_canonical(),
        "different ground_ticket_root, SAME commitment (excluded field)",
    );
    c.extras
        .push(("proposal_commitment", base_commit.as_bytes().to_vec()));
    cases.push(c);

    let mut sig_var = base.clone();
    sig_var.proposer_signature = Bytes96([0xAB; 96]);
    let mut c = positive(
        "commitment-excludes-proposer-signature",
        sig_var.encode_canonical(),
        "different proposer_signature, SAME commitment (excluded field)",
    );
    c.extras
        .push(("proposal_commitment", base_commit.as_bytes().to_vec()));
    cases.push(c);

    let mut recv_var = base.clone();
    recv_var.execution_receipt_root = h(0xA1);
    let mut c = case(
        "commitment-included-field-perturbs",
        "negative",
        base.encode_canonical(),
        "claim derived from a different execution_receipt_root must not match",
    );
    c.extras.push((
        "proposal_commitment",
        recv_var.proposal_commitment().unwrap().as_bytes().to_vec(),
    ));
    cases.push(c);

    let mut c = case(
        "commitment-not-the-block-hash",
        "negative",
        base.encode_canonical(),
        "the D-BLOCK-HEADER block hash is a different domain and coverage",
    );
    c.extras.push((
        "proposal_commitment",
        base.block_hash().unwrap().as_bytes().to_vec(),
    ));
    cases.push(c);

    VectorFile {
        schema: "noos-braid/proposal-commitment-v1",
        cases,
    }
}

fn score_bytes(s: &ForkScore) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&s.finalized_epoch.to_le_bytes());
    out.extend_from_slice(&s.justified_epoch.to_le_bytes());
    out.extend_from_slice(&s.work_since_finalized.to_le_bytes());
    out.extend_from_slice(&s.block_hash);
    out
}

fn score(fin: u64, just: u64, work: U256, hash: [u8; 32]) -> ForkScore {
    ForkScore {
        finalized_epoch: fin,
        justified_epoch: just,
        work_since_finalized: work,
        block_hash: hash,
    }
}

fn fork_case(name: &str, a: ForkScore, b: ForkScore, note: &str) -> Case {
    let mut bytes = score_bytes(&a);
    bytes.extend_from_slice(&score_bytes(&b));
    let mut c = positive(name, bytes, note);
    c.extras_str
        .push(("expected", if a > b { "a" } else { "b" }.to_string()));
    c
}

fn fork_file() -> VectorFile {
    let low = h(0x01);
    let high = h(0x02);
    let cases = vec![
        fork_case(
            "finality-dominates-astronomical-work",
            score(1, 1, U256::from_u64(1), high),
            score(0, 0, U256::MAX, low),
            "a newer finalized checkpoint outranks U256::MAX cumulative work",
        ),
        fork_case(
            "justified-outranks-work",
            score(2, 3, U256::from_u64(5), high),
            score(2, 2, U256::MAX, low),
            "equal finality: higher justified checkpoint outranks work",
        ),
        fork_case(
            "work-decides",
            score(2, 2, U256::from_u64(500), high),
            score(2, 2, U256::from_u64(200), low),
            "equal checkpoints: greater cumulative normalized G+L wins",
        ),
        fork_case(
            "inverse-hash-tiebreak",
            score(2, 2, U256::from_u64(500), high),
            score(2, 2, U256::from_u64(500), low),
            "full tie: the numerically SMALLER hash wins (byte-lexicographic)",
        ),
        fork_case(
            "inverse-hash-last-byte",
            score(0, 0, U256::ZERO, {
                let mut x = h(0x05);
                x[31] = 0x06;
                x
            }),
            score(0, 0, U256::ZERO, h(0x05)),
            "hashes equal except the last byte: still the smaller hash",
        ),
        fork_case(
            "saturated-work-ties-break-on-hash",
            score(3, 3, U256::MAX, low),
            score(3, 3, U256::MAX, high),
            "both branches saturated at U256::MAX: tiebreak decides",
        ),
        fork_case(
            "lexicographic-precedence-order",
            score(2, 2, U256::MAX, low),
            score(2, 3, U256::ZERO, high),
            "justified compares before work: b wins despite zero work",
        ),
    ];
    VectorFile {
        schema: "noos-braid/fork-choice-v1",
        cases,
    }
}

fn body_file() -> VectorFile {
    let minimal = minimal_body();
    let mut cases = Vec::new();

    cases.push(positive(
        "body-minimal",
        minimal.encode_canonical(),
        "empty collections + the mandatory Ground ticket",
    ));

    let mut rich = minimal_body();
    rich.finality_certificates = BoundedList::new(vec![fixture_certificate()]).unwrap();
    rich.consensus_blob_descriptors = BoundedList::new(vec![fixture_blob()]).unwrap();
    rich.system_transitions =
        BoundedList::new(vec![BoundedBytes::new(vec![0xD0; 8]).unwrap()]).unwrap();
    cases.push(positive(
        "body-with-certificate-and-blob",
        rich.encode_canonical(),
        "one finality certificate, one blob descriptor, one system transition",
    ));

    // Nonzero loom_credit_claims count: LengthExceedsBound at decode.
    // Manually splice a count of 1 into the (empty) claims list. The claims
    // list is field tag 6; locate its length prefix by re-encoding the head.
    let canon = minimal.encode_canonical();
    let blob_list_suffix_len = {
        // tag(2) + u32 len for field 7 with zero elements
        2 + 4
    };
    let claims_len_offset = canon.len() - blob_list_suffix_len - 4;
    let mut loom = canon.clone();
    loom[claims_len_offset] = 1;
    cases.push(negative(
        "body-loom-claim-smuggled",
        loom,
        CodecError::LengthExceedsBound,
        "loom_credit_claims count 1 while the lane is disabled (max 0)",
    ));

    let mut nine_certs = minimal_body();
    // Bypass BoundedList::new (which would refuse 9 > 8) by splicing bytes:
    // encode 8 certs, then patch the count and append a ninth element.
    let cert = fixture_certificate();
    nine_certs.finality_certificates = BoundedList::new(vec![cert.clone(); 8]).unwrap();
    let bytes8 = nine_certs.encode_canonical();
    // Field order: 1 txs, 2 witnesses, 3 system, 4 certs...
    // Locate the cert-list length prefix: tag1(2)+len(4) + tag2(2)+len(4)
    // + tag3(2)+len(4) + tag4(2) after the version (2).
    let cert_len_offset = 2 + (2 + 4) * 3 + 2;
    let mut bytes9 = bytes8;
    bytes9[cert_len_offset] = 9;
    let cert_bytes = cert.encode_canonical();
    // Insert one more cert right after the 8 encoded certs.
    let insert_at = cert_len_offset + 4 + 8 * cert_bytes.len();
    for (i, b) in cert_bytes.iter().enumerate() {
        bytes9.insert(insert_at + i, *b);
    }
    cases.push(negative(
        "body-nine-certificates",
        bytes9,
        CodecError::LengthExceedsBound,
        "finality_certificates count 9 exceeds the maximum of 8",
    ));

    let mut trailing = minimal.encode_canonical();
    trailing.push(0xFF);
    cases.push(negative(
        "body-trailing-byte",
        trailing,
        CodecError::TrailingBytes,
        "one byte appended after the canonical encoding",
    ));

    let mut short = minimal.encode_canonical();
    short.truncate(short.len() - (2 + 4) - (2 + 4) - 40);
    cases.push(negative(
        "body-truncated-ticket",
        short,
        CodecError::Truncated,
        "encoding cut inside the 76-byte Ground ticket",
    ));

    VectorFile {
        schema: "noos-braid/body-v1",
        cases,
    }
}

/// Every braid vector file, in emission order.
#[must_use]
pub fn files() -> Vec<(&'static str, VectorFile)> {
    vec![
        ("braid-header-v1.json", header_file()),
        ("braid-header-validation-v1.json", validation_file()),
        ("braid-proposal-commitment-v1.json", commitment_file()),
        ("braid-fork-choice-v1.json", fork_file()),
        ("braid-body-v1.json", body_file()),
    ]
}

/// Renders a vector file as `check_vectors.py`-conformant JSON.
#[must_use]
pub fn render_json(file: &VectorFile) -> String {
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"schema\": \"{}\",\n", file.schema));
    out.push_str("  \"cases\": [\n");
    for (i, c) in file.cases.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        out.push_str(&format!("      \"kind\": \"{}\",\n", c.kind));
        out.push_str(&format!("      \"bytes\": \"{}\",\n", hex(&c.bytes)));
        for (k, v) in &c.extras {
            out.push_str(&format!("      \"{k}\": \"{}\",\n", hex(v)));
        }
        for (k, v) in &c.extras_str {
            out.push_str(&format!("      \"{k}\": \"{v}\",\n"));
        }
        if let Some(err) = c.error_class {
            out.push_str(&format!("      \"error_class\": \"{err}\",\n"));
        }
        out.push_str(&format!("      \"note\": \"{}\"\n", c.note));
        out.push_str(if i + 1 == file.cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    out.push_str("  ]\n}\n");
    out
}
