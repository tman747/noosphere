//! NOOSPHERE canonical consensus codec (plan §3.1).
//!
//! Law:
//! - Every primitive field is fixed-width little-endian.
//! - Every collection is a canonical `u32` little-endian length prefix followed by
//!   exactly `len` elements; `len` is validated against BOTH the per-type maximum and
//!   the remaining input length BEFORE any allocation.
//! - Consensus objects carry an explicit `u16` version and numeric `u16` field tags.
//!   Tags `0x0000..=0x7FFF` are MANDATORY: an unknown mandatory tag rejects.
//!   Tags `0x8000..=0xFFFF` are OPTIONAL: length-prefixed, skippable only where the
//!   object explicitly opts in (consensus objects reject unknown fields by default).
//! - Enum discriminants are `u16` in declaration order; unknown discriminants reject.
//! - Decoding consumes the entire input: trailing bytes reject.
//! - Variable-length unsigned atoms (used by commitment preimages) are minimal:
//!   a leading zero byte in a multi-byte atom rejects (`NonMinimalAtom`).
//!
//! This crate has zero dependencies and performs no I/O; determinism is total.

#![forbid(unsafe_code)]

use core::fmt;

/// Closed decode-error law. Numeric order is stable and part of the protocol:
/// error classes are cross-checked against conformance vectors by class name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecError {
    /// Input ended before a fixed-width field or declared length was satisfied.
    Truncated,
    /// Input bytes remain after the object's canonical encoding was consumed.
    TrailingBytes,
    /// A variable-length atom carried a non-minimal encoding (leading zero byte).
    NonMinimalAtom,
    /// An unrecognized mandatory field tag (`< 0x8000`) was encountered.
    UnknownMandatoryField,
    /// A collection length prefix exceeded the type's declared maximum,
    /// or exceeded the bytes remaining in the input.
    LengthExceedsBound,
    /// The object's version field is not accepted by this decoder.
    UnknownVersion,
    /// An enum discriminant outside declaration order was encountered.
    UnknownDiscriminant,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CodecError::Truncated => "truncated",
            CodecError::TrailingBytes => "trailing_bytes",
            CodecError::NonMinimalAtom => "nonminimal_atom",
            CodecError::UnknownMandatoryField => "unknown_mandatory_field",
            CodecError::LengthExceedsBound => "length_exceeds_bound",
            CodecError::UnknownVersion => "unknown_version",
            CodecError::UnknownDiscriminant => "unknown_discriminant",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CodecError {}

/// Stable class name used by conformance vectors.
impl CodecError {
    pub fn class_name(self) -> &'static str {
        match self {
            CodecError::Truncated => "truncated",
            CodecError::TrailingBytes => "trailing_bytes",
            CodecError::NonMinimalAtom => "nonminimal_atom",
            CodecError::UnknownMandatoryField => "unknown_mandatory_field",
            CodecError::LengthExceedsBound => "length_exceeds_bound",
            CodecError::UnknownVersion => "unknown_version",
            CodecError::UnknownDiscriminant => "unknown_discriminant",
        }
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Canonical encoder. Append-only; never fails.
#[derive(Default, Debug, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Writer { buf: Vec::with_capacity(cap) }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_array32(&mut self, v: &[u8; 32]) {
        self.buf.extend_from_slice(v);
    }

    pub fn put_raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Canonical length-delimited byte string. Caller-supplied `max` is the
    /// per-type bound; encoding an oversized value is a caller bug and panics
    /// in debug (encoders construct only valid objects).
    pub fn put_bytes(&mut self, v: &[u8], max: u32) {
        debug_assert!(v.len() <= max as usize, "encoder produced oversized collection");
        self.put_u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }

    /// Canonical minimal unsigned atom: no leading zero byte; zero encodes as
    /// the empty byte string.
    pub fn put_atom(&mut self, v: &[u8], max: u32) {
        debug_assert!(v.first() != Some(&0), "encoder produced non-minimal atom");
        self.put_bytes(v, max);
    }

    /// Length-prefixed list of encodable items.
    pub fn put_list<T: NoosEncode>(&mut self, items: &[T], max: u32) {
        debug_assert!(items.len() <= max as usize);
        self.put_u32(items.len() as u32);
        for it in items {
            it.encode(self);
        }
    }

    /// Mandatory field tag (`tag < 0x8000`).
    pub fn put_mandatory_tag(&mut self, tag: u16) {
        debug_assert!(tag < 0x8000);
        self.put_u16(tag);
    }

    /// Optional field: tag (`>= 0x8000`) + u32 byte length + payload.
    pub fn put_optional_field(&mut self, tag: u16, payload: &[u8], max: u32) {
        debug_assert!(tag >= 0x8000);
        self.put_u16(tag);
        self.put_bytes(payload, max);
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Strict canonical decoder over a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Reader { input, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError::Truncated);
        }
        let s = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn get_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn get_u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn get_u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn get_u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn get_u128(&mut self) -> Result<u128, CodecError> {
        let b = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(u128::from_le_bytes(a))
    }

    pub fn get_array32(&mut self) -> Result<[u8; 32], CodecError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// Canonical length-delimited byte string, bounded by `max` AND by the
    /// remaining input BEFORE any allocation. A `0xFFFF_FFFF` prefix on a short
    /// input fails without allocating.
    pub fn get_bytes(&mut self, max: u32) -> Result<Vec<u8>, CodecError> {
        let len = self.get_u32()? as usize;
        if len > max as usize || len > self.remaining() {
            return Err(CodecError::LengthExceedsBound);
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Borrowed variant of [`get_bytes`]: zero-copy for hashing paths.
    pub fn get_bytes_ref(&mut self, max: u32) -> Result<&'a [u8], CodecError> {
        let len = self.get_u32()? as usize;
        if len > max as usize || len > self.remaining() {
            return Err(CodecError::LengthExceedsBound);
        }
        self.take(len)
    }

    /// Canonical minimal unsigned atom.
    pub fn get_atom(&mut self, max: u32) -> Result<Vec<u8>, CodecError> {
        let b = self.get_bytes(max)?;
        if b.first() == Some(&0) {
            return Err(CodecError::NonMinimalAtom);
        }
        Ok(b)
    }

    /// Length-prefixed list of decodable items. Element count is bounded by
    /// `max` and, conservatively, by the remaining byte count (each element is
    /// at least one byte in every canonical NOOSPHERE object), so a forged huge
    /// count cannot force allocation.
    pub fn get_list<T: NoosDecode>(&mut self, max: u32) -> Result<Vec<T>, CodecError> {
        let len = self.get_u32()? as usize;
        if len > max as usize || len > self.remaining() {
            return Err(CodecError::LengthExceedsBound);
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::decode(self)?);
        }
        Ok(out)
    }

    /// Version gate: the decoded `u16` must be in `accepted`.
    pub fn expect_version(&mut self, accepted: &[u16]) -> Result<u16, CodecError> {
        let v = self.get_u16()?;
        if accepted.contains(&v) {
            Ok(v)
        } else {
            Err(CodecError::UnknownVersion)
        }
    }

    /// Mandatory field tag: the decoded `u16` must equal `expected`.
    /// Any other mandatory-range tag is `UnknownMandatoryField`; an
    /// optional-range tag in a mandatory position is also unknown-mandatory
    /// (consensus objects declare exact field order).
    pub fn expect_mandatory_tag(&mut self, expected: u16) -> Result<(), CodecError> {
        debug_assert!(expected < 0x8000);
        let t = self.get_u16()?;
        if t == expected {
            Ok(())
        } else {
            Err(CodecError::UnknownMandatoryField)
        }
    }

    /// Enum discriminant gate: `u16` must be `< variant_count` (declaration order).
    pub fn get_discriminant(&mut self, variant_count: u16) -> Result<u16, CodecError> {
        let d = self.get_u16()?;
        if d < variant_count {
            Ok(d)
        } else {
            Err(CodecError::UnknownDiscriminant)
        }
    }

    /// Strict completion: all input must be consumed.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

pub trait NoosEncode {
    fn encode(&self, w: &mut Writer);

    fn encode_canonical(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.into_bytes()
    }
}

pub trait NoosDecode: Sized {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError>;

    /// Whole-input decode: rejects trailing bytes.
    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(input);
        let v = Self::decode(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

// Primitive impls -----------------------------------------------------------

macro_rules! impl_prim {
    ($t:ty, $put:ident, $get:ident) => {
        impl NoosEncode for $t {
            fn encode(&self, w: &mut Writer) {
                w.$put(*self);
            }
        }
        impl NoosDecode for $t {
            fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
                r.$get()
            }
        }
    };
}

impl_prim!(u8, put_u8, get_u8);
impl_prim!(u16, put_u16, get_u16);
impl_prim!(u32, put_u32, get_u32);
impl_prim!(u64, put_u64, get_u64);
impl_prim!(u128, put_u128, get_u128);

impl NoosEncode for [u8; 32] {
    fn encode(&self, w: &mut Writer) {
        w.put_array32(self);
    }
}

impl NoosDecode for [u8; 32] {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.get_array32()
    }
}

// ---------------------------------------------------------------------------
// Object definition macro
// ---------------------------------------------------------------------------

/// Defines a versioned, mandatory-tagged consensus object.
///
/// ```ignore
/// define_object! {
///     /// Example.
///     pub struct DemoV1 {
///         version: 1;
///         1 => alpha: u64,
///         2 => beta: [u8; 32],
///     }
/// }
/// ```
///
/// Encoding: `version:u16` then, per field in declaration order,
/// `tag:u16` followed by the field's canonical encoding. Decoding enforces
/// the exact version, exact tag order, and (via `decode_canonical`) no
/// trailing bytes. Unknown tags reject with `UnknownMandatoryField`.
#[macro_export]
macro_rules! define_object {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            version: $ver:expr;
            $( $tag:expr => $field:ident : $ftype:ty ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $( pub $field: $ftype, )+
        }

        impl $name {
            pub const VERSION: u16 = $ver;
        }

        impl $crate::NoosEncode for $name {
            fn encode(&self, w: &mut $crate::Writer) {
                w.put_u16(Self::VERSION);
                $(
                    w.put_mandatory_tag($tag);
                    $crate::NoosEncode::encode(&self.$field, w);
                )+
            }
        }

        impl $crate::NoosDecode for $name {
            fn decode(r: &mut $crate::Reader<'_>) -> Result<Self, $crate::CodecError> {
                r.expect_version(&[Self::VERSION])?;
                $(
                    r.expect_mandatory_tag($tag)?;
                    let $field = <$ftype as $crate::NoosDecode>::decode(r)?;
                )+
                Ok(Self { $( $field, )+ })
            }
        }
    };
}

#[cfg(test)]
mod tests;
