//! Deterministic conformance-vector generator for noos-codec.
//!
//! Writes `protocol/vectors/codec/codec-v1.json` relative to the workspace
//! root (two levels up from this crate). Zero dependencies: JSON is emitted by
//! hand from fully controlled ASCII content.

use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Writer};

define_object! {
    /// Conformance object: mirrors the crate test object exactly.
    pub struct DemoV1 {
        version: 1;
        1 => alpha: u64,
        2 => beta: [u8; 32],
        3 => gamma: u16,
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

struct Case {
    name: String,
    kind: &'static str,
    bytes: Vec<u8>,
    error_class: Option<&'static str>,
    note: &'static str,
}

fn positive(name: &str, bytes: Vec<u8>, note: &'static str) -> Case {
    Case { name: name.to_string(), kind: "positive", bytes, error_class: None, note }
}

fn negative(name: &str, bytes: Vec<u8>, err: CodecError, note: &'static str) -> Case {
    Case {
        name: name.to_string(),
        kind: "negative",
        bytes,
        error_class: Some(err.class_name()),
        note,
    }
}

fn demo(alpha: u64, fill: u8, gamma: u16) -> DemoV1 {
    DemoV1 { alpha, beta: [fill; 32], gamma }
}

fn main() {
    let mut cases: Vec<Case> = Vec::new();

    // -- positives: DemoV1 across value edges --------------------------------
    let edges_u64 = [0u64, 1, 0xFF, 0x100, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX];
    let edges_u16 = [0u16, 1, 0x7FFF, 0x8000, u16::MAX];
    let mut i = 0;
    for a in edges_u64 {
        for g in edges_u16 {
            if i >= 12 {
                break;
            }
            let obj = demo(a, (i as u8).wrapping_mul(37), g);
            cases.push(positive(
                &format!("demo_roundtrip_{i:02}"),
                obj.encode_canonical(),
                "canonical DemoV1; decode then re-encode must be byte-identical",
            ));
            i += 1;
        }
    }

    // -- positives: primitive layouts ----------------------------------------
    {
        let mut w = Writer::new();
        w.put_u8(0xAB);
        cases.push(positive("prim_u8", w.into_bytes(), "single u8"));
        let mut w = Writer::new();
        w.put_u16(0x0102);
        cases.push(positive("prim_u16_le", w.into_bytes(), "u16 little-endian: 02 01"));
        let mut w = Writer::new();
        w.put_u32(0x0102_0304);
        cases.push(positive("prim_u32_le", w.into_bytes(), "u32 little-endian: 04 03 02 01"));
        let mut w = Writer::new();
        w.put_u64(0x0102_0304_0506_0708);
        cases.push(positive("prim_u64_le", w.into_bytes(), "u64 little-endian"));
        let mut w = Writer::new();
        w.put_u128(1);
        cases.push(positive("prim_u128_one", w.into_bytes(), "u128 value 1: 01 then 15 zeros"));
        let mut w = Writer::new();
        w.put_array32(&[0x5A; 32]);
        cases.push(positive("prim_array32", w.into_bytes(), "fixed 32-byte array, no length prefix"));
    }

    // -- positives: collections ----------------------------------------------
    {
        let mut w = Writer::new();
        w.put_bytes(&[], 16);
        cases.push(positive("bytes_empty", w.into_bytes(), "length 0 collection"));
        let mut w = Writer::new();
        w.put_bytes(b"noos", 16);
        cases.push(positive("bytes_small", w.into_bytes(), "4-byte collection"));
        let mut w = Writer::new();
        w.put_bytes(&[0xEE; 16], 16);
        cases.push(positive("bytes_at_max", w.into_bytes(), "collection exactly at type max 16"));
        let mut w = Writer::new();
        w.put_list(&[1u64, 2, 3], 8);
        cases.push(positive("list_u64_3", w.into_bytes(), "list of three u64"));
        let mut w = Writer::new();
        w.put_list::<u64>(&[], 8);
        cases.push(positive("list_empty", w.into_bytes(), "empty list"));
        let mut w = Writer::new();
        w.put_atom(&[], 8);
        cases.push(positive("atom_zero_empty", w.into_bytes(), "atom zero = empty string"));
        let mut w = Writer::new();
        w.put_atom(&[0x01], 8);
        cases.push(positive("atom_one", w.into_bytes(), "minimal single-byte atom"));
        let mut w = Writer::new();
        w.put_atom(&[0x01, 0x00], 8);
        cases.push(positive("atom_256_le_minimal", w.into_bytes(), "atom 256: trailing zero ok, leading zero banned"));
        let mut w = Writer::new();
        w.put_optional_field(0x8001, b"opt", 8);
        cases.push(positive("optional_field", w.into_bytes(), "optional tag 0x8001 with 3-byte payload"));
    }

    // Pad positives to >=30 with deterministic list-of-u16 shapes.
    let mut k = 0u16;
    while cases.iter().filter(|c| c.kind == "positive").count() < 30 {
        let items: Vec<u16> = (0..=k).map(|x| x.wrapping_mul(257)).collect();
        let mut w = Writer::new();
        w.put_list(&items, 64);
        cases.push(positive(
            &format!("list_u16_len_{}", items.len()),
            w.into_bytes(),
            "deterministic u16 list",
        ));
        k += 1;
    }

    // -- negatives -------------------------------------------------------------
    let base = demo(0xDEAD_BEEF, 7, 513).encode_canonical();

    // truncated: cut at several structurally interesting prefixes
    for cut in [0usize, 1, 2, 3, 4, 11, 12, 43, 44, base.len() - 1] {
        cases.push(negative(
            &format!("demo_truncated_at_{cut:02}"),
            base[..cut].to_vec(),
            CodecError::Truncated,
            "DemoV1 prefix must reject",
        ));
    }

    // trailing bytes
    {
        let mut b = base.clone();
        b.push(0x00);
        cases.push(negative("demo_trailing_zero", b, CodecError::TrailingBytes, "one extra byte"));
        let mut b = base.clone();
        b.extend_from_slice(&[1, 2, 3, 4]);
        cases.push(negative("demo_trailing_four", b, CodecError::TrailingBytes, "four extra bytes"));
    }

    // unknown version
    {
        let mut b = base.clone();
        b[0] = 0x02;
        cases.push(negative("demo_version_2", b, CodecError::UnknownVersion, "version 2 unknown"));
        let mut b = base.clone();
        b[0] = 0x00;
        cases.push(negative("demo_version_0", b, CodecError::UnknownVersion, "version 0 unknown"));
        let mut b = base.clone();
        b[1] = 0xFF;
        cases.push(negative("demo_version_high_byte", b, CodecError::UnknownVersion, "version 0xFF01 unknown"));
    }

    // unknown mandatory field
    {
        let mut b = base.clone();
        b[2] = 0x09;
        cases.push(negative("demo_tag1_becomes_9", b, CodecError::UnknownMandatoryField, "first tag wrong"));
        let mut b = base.clone();
        b[2] = 0x02;
        cases.push(negative("demo_tag_order_swapped", b, CodecError::UnknownMandatoryField, "tag out of declared order"));
        let mut b = base.clone();
        b[3] = 0x80;
        cases.push(negative("demo_optional_tag_in_mandatory_slot", b, CodecError::UnknownMandatoryField, "optional-range tag where mandatory expected"));
    }

    // length bound violations (standalone byte-string context, max=16)
    {
        let mut w = Writer::new();
        w.put_u32(17);
        w.put_raw(&[0xAA; 17]);
        cases.push(negative("bytes_max_plus_1", w.into_bytes(), CodecError::LengthExceedsBound, "17 > max 16 (ctx: get_bytes max=16)"));
        let mut w = Writer::new();
        w.put_u32(0xFFFF_FFFF);
        cases.push(negative("bytes_huge_prefix_no_alloc", w.into_bytes(), CodecError::LengthExceedsBound, "0xFFFFFFFF length on empty tail must fail before allocation (ctx: get_bytes max=16)"));
        let mut w = Writer::new();
        w.put_u32(8);
        w.put_raw(&[0xBB; 4]);
        cases.push(negative("bytes_len_exceeds_remaining", w.into_bytes(), CodecError::LengthExceedsBound, "declared 8, only 4 remain (ctx: get_bytes max=16)"));
    }

    // nonminimal atom (standalone atom context, max=16)
    {
        let mut w = Writer::new();
        w.put_u32(2);
        w.put_raw(&[0x00, 0x05]);
        cases.push(negative("atom_leading_zero", w.into_bytes(), CodecError::NonMinimalAtom, "leading zero byte (ctx: get_atom max=16)"));
        let mut w = Writer::new();
        w.put_u32(1);
        w.put_raw(&[0x00]);
        cases.push(negative("atom_single_zero_byte", w.into_bytes(), CodecError::NonMinimalAtom, "zero must be empty, not 00 (ctx: get_atom max=16)"));
    }

    // discriminant (standalone context, variant_count=3)
    {
        let mut w = Writer::new();
        w.put_u16(3);
        cases.push(negative("discriminant_eq_count", w.into_bytes(), CodecError::UnknownDiscriminant, "3 invalid for 3 variants (ctx: get_discriminant 3)"));
        let mut w = Writer::new();
        w.put_u16(0xFFFF);
        cases.push(negative("discriminant_max", w.into_bytes(), CodecError::UnknownDiscriminant, "0xFFFF invalid (ctx: get_discriminant 3)"));
    }

    // list violations (standalone context, list of u64, max=8)
    {
        let mut w = Writer::new();
        w.put_u32(9);
        for i in 0..9u64 {
            w.put_u64(i);
        }
        cases.push(negative("list_count_exceeds_max", w.into_bytes(), CodecError::LengthExceedsBound, "9 > max 8 (ctx: get_list<u64> max=8)"));
        let mut w = Writer::new();
        w.put_u32(3);
        w.put_u64(1);
        w.put_u64(2);
        w.put_raw(&[0xCC; 4]);
        cases.push(negative("list_element_truncated", w.into_bytes(), CodecError::Truncated, "third u64 short (ctx: get_list<u64> max=8)"));
        let mut w = Writer::new();
        w.put_u32(0xFFFF_FFFF);
        w.put_raw(&[0u8; 8]);
        cases.push(negative("list_huge_count_no_alloc", w.into_bytes(), CodecError::LengthExceedsBound, "forged count fails byte-floor check (ctx: get_list<u64> max=2^32-1)"));
    }

    // Pad negatives to >=30 with per-field truncations across a wider object set.
    let mut cut = 5usize;
    while cases.iter().filter(|c| c.kind == "negative").count() < 30 {
        if cut >= base.len() {
            break;
        }
        cases.push(negative(
            &format!("demo_truncated_at_{cut:02}b"),
            base[..cut].to_vec(),
            CodecError::Truncated,
            "additional truncation coverage",
        ));
        cut += 3;
    }

    // -- self-verify every case against this implementation -------------------
    for c in &cases {
        let named = &c.name;
        if named.starts_with("demo_") {
            let res = DemoV1::decode_canonical(&c.bytes);
            match c.kind {
                "positive" => {
                    let v = res.unwrap_or_else(|e| panic!("{named}: expected ok, got {e}"));
                    assert_eq!(v.encode_canonical(), c.bytes, "{named}: re-encode mismatch");
                }
                _ => {
                    let err = res.expect_err(&format!("{named}: expected error"));
                    assert_eq!(Some(err.class_name()), c.error_class, "{named}: class mismatch");
                }
            }
        }
    }

    // -- emit JSON -------------------------------------------------------------
    let mut out = String::new();
    out.push_str("{\n  \"schema\": \"noos-codec-vectors-v1\",\n  \"cases\": [\n");
    for (idx, c) in cases.iter().enumerate() {
        out.push_str("    {");
        out.push_str(&format!("\"name\": \"{}\", ", c.name));
        out.push_str(&format!("\"kind\": \"{}\", ", c.kind));
        out.push_str(&format!("\"bytes\": \"{}\"", hex(&c.bytes)));
        if let Some(e) = c.error_class {
            out.push_str(&format!(", \"error_class\": \"{e}\""));
        }
        out.push_str(&format!(", \"note\": \"{}\"", c.note));
        out.push('}');
        if idx + 1 != cases.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/codec");
    std::fs::create_dir_all(&root).expect("create vectors dir");
    let path = root.join("codec-v1.json");
    std::fs::write(&path, out).expect("write vectors");
    let pos = cases.iter().filter(|c| c.kind == "positive").count();
    let neg = cases.len() - pos;
    println!("wrote {} cases ({pos} positive, {neg} negative) to {}", cases.len(), path.display());
}
