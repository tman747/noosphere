use crate::{CodecError, NoosDecode, NoosEncode, Reader, Writer};

define_object! {
    /// Test object exercising every primitive width plus a bounded collection.
    pub struct DemoV1 {
        version: 1;
        1 => alpha: u64,
        2 => beta: [u8; 32],
        3 => gamma: u16,
    }
}

fn demo() -> DemoV1 {
    DemoV1 { alpha: 0xDEAD_BEEF_0102_0304, beta: [7u8; 32], gamma: 513 }
}

// -- roundtrips --------------------------------------------------------------

#[test]
fn roundtrip_primitives() {
    let mut w = Writer::new();
    w.put_u8(0xAB);
    w.put_u16(0xCDEF);
    w.put_u32(0x0123_4567);
    w.put_u64(0x89AB_CDEF_0123_4567);
    w.put_u128(0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF);
    w.put_array32(&[9u8; 32]);
    let bytes = w.into_bytes();
    assert_eq!(bytes.len(), 1 + 2 + 4 + 8 + 16 + 32);

    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_u8().unwrap(), 0xAB);
    assert_eq!(r.get_u16().unwrap(), 0xCDEF);
    assert_eq!(r.get_u32().unwrap(), 0x0123_4567);
    assert_eq!(r.get_u64().unwrap(), 0x89AB_CDEF_0123_4567);
    assert_eq!(r.get_u128().unwrap(), 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF);
    assert_eq!(r.get_array32().unwrap(), [9u8; 32]);
    r.finish().unwrap();
}

#[test]
fn little_endian_layout_is_exact() {
    let mut w = Writer::new();
    w.put_u32(0x0102_0304);
    assert_eq!(w.as_bytes(), &[0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn roundtrip_bytes_and_lists() {
    let mut w = Writer::new();
    w.put_bytes(b"hello", 16);
    w.put_list(&[1u64, 2, 3], 8);
    let bytes = w.into_bytes();

    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_bytes(16).unwrap(), b"hello");
    assert_eq!(r.get_list::<u64>(8).unwrap(), vec![1, 2, 3]);
    r.finish().unwrap();
}

#[test]
fn roundtrip_object() {
    let d = demo();
    let bytes = d.encode_canonical();
    let back = DemoV1::decode_canonical(&bytes).unwrap();
    assert_eq!(back, d);
}

// -- negative classes ---------------------------------------------------------

#[test]
fn truncated_every_prefix_rejects() {
    let bytes = demo().encode_canonical();
    for cut in 0..bytes.len() {
        let err = DemoV1::decode_canonical(&bytes[..cut]).unwrap_err();
        assert!(
            matches!(err, CodecError::Truncated | CodecError::LengthExceedsBound),
            "cut {cut} gave {err:?}"
        );
    }
}

#[test]
fn trailing_bytes_reject() {
    let mut bytes = demo().encode_canonical();
    bytes.push(0);
    assert_eq!(DemoV1::decode_canonical(&bytes).unwrap_err(), CodecError::TrailingBytes);
}

#[test]
fn nonminimal_atom_rejects() {
    let mut w = Writer::new();
    // Hand-craft a non-minimal atom: length 2, leading zero.
    w.put_u32(2);
    w.put_raw(&[0x00, 0x05]);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_atom(8).unwrap_err(), CodecError::NonMinimalAtom);
}

#[test]
fn atom_zero_is_empty_and_valid() {
    let mut w = Writer::new();
    w.put_atom(&[], 8);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_atom(8).unwrap(), Vec::<u8>::new());
    r.finish().unwrap();
}

#[test]
fn unknown_version_rejects() {
    let mut bytes = demo().encode_canonical();
    bytes[0] = 2; // version LE low byte
    assert_eq!(DemoV1::decode_canonical(&bytes).unwrap_err(), CodecError::UnknownVersion);
}

#[test]
fn unknown_mandatory_field_rejects() {
    let mut bytes = demo().encode_canonical();
    // First tag is at offset 2 (after version u16); change 1 -> 9.
    bytes[2] = 9;
    assert_eq!(DemoV1::decode_canonical(&bytes).unwrap_err(), CodecError::UnknownMandatoryField);
}

#[test]
fn optional_tag_in_mandatory_position_rejects() {
    let mut bytes = demo().encode_canonical();
    bytes[3] = 0x80; // tag high byte -> 0x8001
    assert_eq!(DemoV1::decode_canonical(&bytes).unwrap_err(), CodecError::UnknownMandatoryField);
}

#[test]
fn unknown_discriminant_rejects() {
    let mut w = Writer::new();
    w.put_u16(3);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_discriminant(3).unwrap_err(), CodecError::UnknownDiscriminant);
    let mut w = Writer::new();
    w.put_u16(2);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_discriminant(3).unwrap(), 2);
}

// -- bounds -------------------------------------------------------------------

#[test]
fn length_boundary_zero_max_maxplus1() {
    // len == 0
    let mut w = Writer::new();
    w.put_bytes(&[], 4);
    let b = w.into_bytes();
    assert_eq!(Reader::new(&b).get_bytes(4).unwrap(), Vec::<u8>::new());

    // len == max
    let mut w = Writer::new();
    w.put_bytes(&[1, 2, 3, 4], 4);
    let b = w.into_bytes();
    assert_eq!(Reader::new(&b).get_bytes(4).unwrap(), vec![1, 2, 3, 4]);

    // len == max + 1 (hand-crafted; encoder debug-asserts)
    let mut w = Writer::new();
    w.put_u32(5);
    w.put_raw(&[1, 2, 3, 4, 5]);
    let b = w.into_bytes();
    assert_eq!(Reader::new(&b).get_bytes(4).unwrap_err(), CodecError::LengthExceedsBound);
}

#[test]
fn huge_length_prefix_fails_before_allocation() {
    // 0xFFFFFFFF declared length on a 4-byte input: must fail via the
    // remaining-bytes bound without ever allocating.
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF];
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_bytes(u32::MAX).unwrap_err(), CodecError::LengthExceedsBound);

    // Same for lists.
    let mut input = vec![0xFF, 0xFF, 0xFF, 0xFF];
    input.extend_from_slice(&[0u8; 8]);
    let mut r = Reader::new(&input);
    assert_eq!(r.get_list::<u64>(u32::MAX).unwrap_err(), CodecError::LengthExceedsBound);
}

#[test]
fn list_count_exceeding_type_max_rejects() {
    let mut w = Writer::new();
    w.put_list(&[1u8, 2, 3], 8);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_list::<u8>(2).unwrap_err(), CodecError::LengthExceedsBound);
}

#[test]
fn list_element_truncation_rejects() {
    // Declared 3 u64 elements but only 2 present: count passes the byte-floor
    // check (3 <= 20 remaining), then element decode hits Truncated.
    let mut w = Writer::new();
    w.put_u32(3);
    w.put_u64(1);
    w.put_u64(2);
    w.put_raw(&[0xAA; 4]);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.get_list::<u64>(8).unwrap_err(), CodecError::Truncated);
}

// -- optional fields ----------------------------------------------------------

#[test]
fn optional_field_roundtrip() {
    let mut w = Writer::new();
    w.put_optional_field(0x8001, b"opt", 8);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    let tag = r.get_u16().unwrap();
    assert_eq!(tag, 0x8001);
    assert_eq!(r.get_bytes(8).unwrap(), b"opt");
    r.finish().unwrap();
}
