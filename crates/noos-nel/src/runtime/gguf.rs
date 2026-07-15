use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::Path;

const GGUF_MAGIC: [u8; 4] = *b"GGUF";
const SUPPORTED_GGUF_VERSION: u32 = 3;
const Q1_0_TYPE: u32 = 41;
const F32_TYPE: u32 = 0;
const Q1_0_BLOCK_ELEMENTS: u64 = 128;
const Q1_0_BLOCK_BYTES: u64 = 18;
const EXPECTED_FILE_TYPE: u64 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedStream {
    pub byte_length: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GgufLimits {
    pub max_metadata: u64,
    pub max_tensors: u64,
    pub max_rank: u32,
    pub max_name_bytes: u64,
    pub max_string_bytes: u64,
    pub max_array_elements: u64,
    pub max_header_bytes: u64,
}

impl Default for GgufLimits {
    fn default() -> Self {
        Self {
            max_metadata: 4_096,
            max_tensors: 16_384,
            max_rank: 4,
            max_name_bytes: 1_024,
            max_string_bytes: 1_048_576,
            max_array_elements: 1_000_000,
            max_header_bytes: 67_108_864,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataSummary {
    Unsigned(u64),
    Signed(i64),
    FloatBits(u64),
    Bool(bool),
    Text(String),
    Array {
        element_type: u32,
        count: u64,
        content_root: [u8; 32],
    },
}

impl MetadataSummary {
    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            _ => None,
        }
    }

    fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    fn array(&self) -> Option<(u32, u64)> {
        match self {
            Self::Array {
                element_type,
                count,
                ..
            } => Some((*element_type, *count)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TensorInfo {
    pub name: String,
    pub dimensions: Vec<u64>,
    pub ggml_type: u32,
    pub offset: u64,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgufInspection {
    pub stream: VerifiedStream,
    pub gguf_version: u32,
    pub architecture: String,
    pub model_name: String,
    pub declared_context_tokens: u32,
    pub tokenizer_model: String,
    pub tokenizer_pretokenizer: String,
    pub tokenizer_token_count: u64,
    pub tokenizer_merge_count: u64,
    pub bos_token_id: u32,
    pub eos_token_id: u32,
    pub padding_token_id: u32,
    pub alignment: u32,
    pub data_offset: u64,
    pub metadata_count: u64,
    pub tensor_count: u64,
    pub q1_tensor_count: u64,
    pub f32_tensor_count: u64,
    pub metadata_root: [u8; 32],
    pub tensor_table_root: [u8; 32],
    pub tokenizer_root: [u8; 32],
    pub chat_template_root: [u8; 32],
    pub metadata: BTreeMap<String, MetadataSummary>,
    pub tensors: Vec<TensorInfo>,
}

impl GgufInspection {
    #[must_use]
    pub fn retained_bytes_upper_bound(&self) -> usize {
        let metadata = self
            .metadata
            .iter()
            .map(|(key, value)| {
                key.len()
                    + match value {
                        MetadataSummary::Text(text) => text.len(),
                        _ => 32,
                    }
            })
            .sum::<usize>();
        let tensors = self
            .tensors
            .iter()
            .map(|tensor| tensor.name.len() + tensor.dimensions.len() * 8 + 32)
            .sum::<usize>();
        metadata.saturating_add(tensors)
    }
}

#[derive(Debug)]
pub enum GgufError {
    Io(io::Error),
    LengthMismatch {
        expected: u64,
        actual: u64,
    },
    Sha256Mismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    InvalidMagic,
    UnsupportedVersion(u32),
    LimitExceeded(&'static str),
    InvalidUtf8,
    DuplicateMetadata(String),
    DuplicateTensor(String),
    InvalidMetadata(&'static str),
    UnsupportedArchitecture(String),
    UnsupportedQuantization,
    UnsupportedTensorType(u32),
    InvalidTensor(&'static str),
    TensorOverlap,
    TensorOutOfBounds,
    NonZeroHeaderPadding,
    TrailingOrMissingTensorBytes,
    IntegerOverflow,
}

impl PartialEq for GgufError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self}") == format!("{other}")
    }
}

impl Eq for GgufError {}

impl fmt::Display for GgufError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "length mismatch: expected {expected}, got {actual}")
            }
            Self::Sha256Mismatch { expected, actual } => write!(
                f,
                "SHA-256 mismatch: expected {}, got {}",
                hex(expected),
                hex(actual)
            ),
            Self::InvalidMagic => write!(f, "invalid GGUF magic"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported GGUF version {version}"),
            Self::LimitExceeded(name) => write!(f, "GGUF limit exceeded: {name}"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in GGUF header"),
            Self::DuplicateMetadata(key) => write!(f, "duplicate metadata key {key}"),
            Self::DuplicateTensor(name) => write!(f, "duplicate tensor name {name}"),
            Self::InvalidMetadata(name) => write!(f, "invalid or ambiguous metadata: {name}"),
            Self::UnsupportedArchitecture(name) => write!(f, "unsupported architecture {name}"),
            Self::UnsupportedQuantization => write!(f, "unsupported Q1 semantics"),
            Self::UnsupportedTensorType(value) => write!(f, "unsupported tensor type {value}"),
            Self::InvalidTensor(reason) => write!(f, "invalid tensor: {reason}"),
            Self::TensorOverlap => write!(f, "overlapping tensors"),
            Self::TensorOutOfBounds => write!(f, "tensor outside file"),
            Self::NonZeroHeaderPadding => write!(f, "non-zero GGUF header padding"),
            Self::TrailingOrMissingTensorBytes => write!(f, "trailing or missing tensor bytes"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
        }
    }
}

impl std::error::Error for GgufError {}

impl From<io::Error> for GgufError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn stream_verify<R: Read>(
    mut reader: R,
    expected_length: u64,
    expected_sha256: [u8; 32],
) -> Result<VerifiedStream, GgufError> {
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| GgufError::IntegerOverflow)?)
            .ok_or(GgufError::IntegerOverflow)?;
        if length > expected_length {
            return Err(GgufError::LengthMismatch {
                expected: expected_length,
                actual: length,
            });
        }
        hasher.update(&buffer[..read]);
    }
    if length != expected_length {
        return Err(GgufError::LengthMismatch {
            expected: expected_length,
            actual: length,
        });
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected_sha256 {
        return Err(GgufError::Sha256Mismatch {
            expected: expected_sha256,
            actual,
        });
    }
    Ok(VerifiedStream {
        byte_length: length,
        sha256: actual,
    })
}

pub fn inspect_gguf_path(
    path: impl AsRef<Path>,
    expected_length: u64,
    expected_sha256: [u8; 32],
    limits: GgufLimits,
) -> Result<GgufInspection, GgufError> {
    let stream = stream_verify(File::open(path.as_ref())?, expected_length, expected_sha256)?;
    inspect_gguf(File::open(path)?, stream, limits)
}

pub fn inspect_gguf<R: Read + Seek>(
    reader: R,
    stream: VerifiedStream,
    limits: GgufLimits,
) -> Result<GgufInspection, GgufError> {
    Parser::new(reader, stream, limits).inspect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamValidation {
    None,
    Utf8,
    Boolean,
}

struct Parser<R> {
    reader: R,
    stream: VerifiedStream,
    limits: GgufLimits,
}

impl<R: Read + Seek> Parser<R> {
    fn new(reader: R, stream: VerifiedStream, limits: GgufLimits) -> Self {
        Self {
            reader,
            stream,
            limits,
        }
    }

    fn inspect(mut self) -> Result<GgufInspection, GgufError> {
        if self.read_array::<4>()? != GGUF_MAGIC {
            return Err(GgufError::InvalidMagic);
        }
        let version = self.read_u32()?;
        if version != SUPPORTED_GGUF_VERSION {
            return Err(GgufError::UnsupportedVersion(version));
        }
        let tensor_count = self.read_u64()?;
        let metadata_count = self.read_u64()?;
        if tensor_count == 0 || tensor_count > self.limits.max_tensors {
            return Err(GgufError::LimitExceeded("tensor_count"));
        }
        if metadata_count == 0 || metadata_count > self.limits.max_metadata {
            return Err(GgufError::LimitExceeded("metadata_count"));
        }

        let mut metadata = BTreeMap::new();
        let mut metadata_keys = BTreeSet::new();
        let mut metadata_hasher = blake3::Hasher::new();
        metadata_hasher.update(b"NOOS/WWM/GGUF-METADATA/V2");
        for _ in 0..metadata_count {
            let key_bytes = self.read_bounded_bytes(self.limits.max_name_bytes)?;
            let key = String::from_utf8(key_bytes.clone()).map_err(|_| GgufError::InvalidUtf8)?;
            if !metadata_keys.insert(key.clone()) {
                return Err(GgufError::DuplicateMetadata(key));
            }
            metadata_hasher.update(
                &u64::try_from(key_bytes.len())
                    .map_err(|_| GgufError::IntegerOverflow)?
                    .to_le_bytes(),
            );
            metadata_hasher.update(&key_bytes);
            let value_type_bytes = self.read_array::<4>()?;
            metadata_hasher.update(&value_type_bytes);
            let value_type = u32::from_le_bytes(value_type_bytes);
            let value = self.read_metadata_value(value_type, &mut metadata_hasher)?;
            metadata.insert(key, value);
            self.check_header_limit()?;
        }
        let metadata_root = *metadata_hasher.finalize().as_bytes();

        let mut tensors = Vec::with_capacity(
            usize::try_from(tensor_count).map_err(|_| GgufError::IntegerOverflow)?,
        );
        let mut tensor_names = BTreeSet::new();
        let mut table_hasher = blake3::Hasher::new();
        table_hasher.update(b"NOOS/WWM/GGUF-TENSOR-TABLE/V2");
        for _ in 0..tensor_count {
            let name_bytes = self.read_bounded_bytes(self.limits.max_name_bytes)?;
            let name = String::from_utf8(name_bytes.clone()).map_err(|_| GgufError::InvalidUtf8)?;
            if !tensor_names.insert(name.clone()) {
                return Err(GgufError::DuplicateTensor(name));
            }
            table_hasher.update(
                &u64::try_from(name_bytes.len())
                    .map_err(|_| GgufError::IntegerOverflow)?
                    .to_le_bytes(),
            );
            table_hasher.update(&name_bytes);
            let rank_bytes = self.read_array::<4>()?;
            table_hasher.update(&rank_bytes);
            let rank = u32::from_le_bytes(rank_bytes);
            if rank == 0 || rank > self.limits.max_rank {
                return Err(GgufError::LimitExceeded("tensor_rank"));
            }
            let mut dimensions =
                Vec::with_capacity(usize::try_from(rank).map_err(|_| GgufError::IntegerOverflow)?);
            for _ in 0..rank {
                let bytes = self.read_array::<8>()?;
                table_hasher.update(&bytes);
                let dimension = u64::from_le_bytes(bytes);
                if dimension == 0 {
                    return Err(GgufError::InvalidTensor("zero dimension"));
                }
                dimensions.push(dimension);
            }
            let type_bytes = self.read_array::<4>()?;
            table_hasher.update(&type_bytes);
            let ggml_type = u32::from_le_bytes(type_bytes);
            let offset_bytes = self.read_array::<8>()?;
            table_hasher.update(&offset_bytes);
            let offset = u64::from_le_bytes(offset_bytes);
            let byte_length = tensor_byte_length(ggml_type, &dimensions)?;
            tensors.push(TensorInfo {
                name,
                dimensions,
                ggml_type,
                offset,
                byte_length,
            });
            self.check_header_limit()?;
        }
        let tensor_table_root = *table_hasher.finalize().as_bytes();
        let header_end = self.reader.stream_position()?;
        let alignment_u64 = metadata
            .get("general.alignment")
            .map_or(Some(32), MetadataSummary::as_u64)
            .ok_or(GgufError::InvalidMetadata("general.alignment"))?;
        let alignment = u32::try_from(alignment_u64)
            .map_err(|_| GgufError::InvalidMetadata("general.alignment"))?;
        if alignment < 16 || alignment > 4_096 || !alignment.is_power_of_two() {
            return Err(GgufError::InvalidMetadata("general.alignment"));
        }
        let data_offset = align_up(header_end, u64::from(alignment))?;
        let padding_length = data_offset
            .checked_sub(header_end)
            .ok_or(GgufError::IntegerOverflow)?;
        let mut remaining_padding = padding_length;
        let mut padding = [0_u8; 4096];
        while remaining_padding != 0 {
            let chunk = usize::try_from(remaining_padding.min(padding.len() as u64))
                .map_err(|_| GgufError::IntegerOverflow)?;
            self.reader.read_exact(&mut padding[..chunk])?;
            if padding[..chunk].iter().any(|byte| *byte != 0) {
                return Err(GgufError::NonZeroHeaderPadding);
            }
            remaining_padding -= u64::try_from(chunk).map_err(|_| GgufError::IntegerOverflow)?;
        }

        let mut sorted = tensors.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|tensor| tensor.offset);
        let mut prior_end = 0_u64;
        for tensor in &sorted {
            if tensor.offset % u64::from(alignment) != 0 {
                return Err(GgufError::InvalidTensor("unaligned offset"));
            }
            if tensor.offset < prior_end {
                return Err(GgufError::TensorOverlap);
            }
            prior_end = tensor
                .offset
                .checked_add(tensor.byte_length)
                .ok_or(GgufError::IntegerOverflow)?;
            let absolute_end = data_offset
                .checked_add(prior_end)
                .ok_or(GgufError::IntegerOverflow)?;
            if absolute_end > self.stream.byte_length {
                return Err(GgufError::TensorOutOfBounds);
            }
        }
        if data_offset
            .checked_add(prior_end)
            .ok_or(GgufError::IntegerOverflow)?
            != self.stream.byte_length
        {
            return Err(GgufError::TrailingOrMissingTensorBytes);
        }

        let architecture = required_text(&metadata, "general.architecture")?.to_owned();
        if architecture != "qwen35" {
            return Err(GgufError::UnsupportedArchitecture(architecture));
        }
        if required_u64(&metadata, "general.quantization_version")? != 2
            || required_u64(&metadata, "general.file_type")? != EXPECTED_FILE_TYPE
        {
            return Err(GgufError::UnsupportedQuantization);
        }
        let q1_tensor_count = u64::try_from(
            tensors
                .iter()
                .filter(|tensor| tensor.ggml_type == Q1_0_TYPE)
                .count(),
        )
        .map_err(|_| GgufError::IntegerOverflow)?;
        let f32_tensor_count = u64::try_from(
            tensors
                .iter()
                .filter(|tensor| tensor.ggml_type == F32_TYPE)
                .count(),
        )
        .map_err(|_| GgufError::IntegerOverflow)?;
        if q1_tensor_count == 0
            || q1_tensor_count.checked_add(f32_tensor_count) != Some(tensor_count)
        {
            return Err(GgufError::UnsupportedQuantization);
        }

        let (token_element, token_count) = required_array(&metadata, "tokenizer.ggml.tokens")?;
        let (type_element, type_count) = required_array(&metadata, "tokenizer.ggml.token_type")?;
        let (merge_element, merge_count) = required_array(&metadata, "tokenizer.ggml.merges")?;
        if token_element != 8
            || type_element != 5
            || merge_element != 8
            || token_count != type_count
        {
            return Err(GgufError::InvalidMetadata("tokenizer arrays"));
        }
        let bos = required_token_id(&metadata, "tokenizer.ggml.bos_token_id", token_count)?;
        let eos = required_token_id(&metadata, "tokenizer.ggml.eos_token_id", token_count)?;
        let padding = required_token_id(&metadata, "tokenizer.ggml.padding_token_id", token_count)?;
        if !matches!(
            metadata.get("tokenizer.ggml.add_bos_token"),
            Some(MetadataSummary::Bool(false))
        ) {
            return Err(GgufError::InvalidMetadata("tokenizer.ggml.add_bos_token"));
        }
        let tokenizer_model = required_text(&metadata, "tokenizer.ggml.model")?.to_owned();
        let tokenizer_pretokenizer = required_text(&metadata, "tokenizer.ggml.pre")?.to_owned();
        if tokenizer_model != "gpt2" || tokenizer_pretokenizer != "qwen35" {
            return Err(GgufError::InvalidMetadata("tokenizer model"));
        }
        let template = required_text(&metadata, "tokenizer.chat_template")?;
        if template.is_empty() {
            return Err(GgufError::InvalidMetadata("tokenizer.chat_template"));
        }
        let context = required_u64(&metadata, "qwen35.context_length")?;
        if !(4_096..=1_048_576).contains(&context) {
            return Err(GgufError::InvalidMetadata("qwen35.context_length"));
        }
        let declared_context_tokens = u32::try_from(context)
            .map_err(|_| GgufError::InvalidMetadata("qwen35.context_length"))?;
        let tokenizer_root = match metadata.get("tokenizer.ggml.tokens") {
            Some(MetadataSummary::Array { content_root, .. }) => *content_root,
            _ => return Err(GgufError::InvalidMetadata("tokenizer.ggml.tokens")),
        };
        let chat_template_root = *blake3::hash(template.as_bytes()).as_bytes();

        Ok(GgufInspection {
            stream: self.stream,
            gguf_version: version,
            architecture,
            model_name: required_text(&metadata, "general.name")?.to_owned(),
            declared_context_tokens,
            tokenizer_model,
            tokenizer_pretokenizer,
            tokenizer_token_count: token_count,
            tokenizer_merge_count: merge_count,
            bos_token_id: bos,
            eos_token_id: eos,
            padding_token_id: padding,
            alignment,
            data_offset,
            metadata_count,
            tensor_count,
            q1_tensor_count,
            f32_tensor_count,
            metadata_root,
            tensor_table_root,
            tokenizer_root,
            chat_template_root,
            metadata,
            tensors,
        })
    }

    fn read_metadata_value(
        &mut self,
        value_type: u32,
        hasher: &mut blake3::Hasher,
    ) -> Result<MetadataSummary, GgufError> {
        match value_type {
            0 => Ok(MetadataSummary::Unsigned(u64::from(
                self.read_hashed::<1>(hasher)?[0],
            ))),
            1 => Ok(MetadataSummary::Signed(i64::from(i8::from_le_bytes(
                self.read_hashed::<1>(hasher)?,
            )))),
            2 => Ok(MetadataSummary::Unsigned(u64::from(u16::from_le_bytes(
                self.read_hashed::<2>(hasher)?,
            )))),
            3 => Ok(MetadataSummary::Signed(i64::from(i16::from_le_bytes(
                self.read_hashed::<2>(hasher)?,
            )))),
            4 => Ok(MetadataSummary::Unsigned(u64::from(u32::from_le_bytes(
                self.read_hashed::<4>(hasher)?,
            )))),
            5 => Ok(MetadataSummary::Signed(i64::from(i32::from_le_bytes(
                self.read_hashed::<4>(hasher)?,
            )))),
            6 => Ok(MetadataSummary::FloatBits(u64::from(u32::from_le_bytes(
                self.read_hashed::<4>(hasher)?,
            )))),
            7 => match self.read_hashed::<1>(hasher)?[0] {
                0 => Ok(MetadataSummary::Bool(false)),
                1 => Ok(MetadataSummary::Bool(true)),
                _ => Err(GgufError::InvalidMetadata("boolean")),
            },
            8 => {
                let bytes = self.read_hashed_bounded_bytes(self.limits.max_string_bytes, hasher)?;
                Ok(MetadataSummary::Text(
                    String::from_utf8(bytes).map_err(|_| GgufError::InvalidUtf8)?,
                ))
            }
            9 => self.read_array_summary(hasher),
            10 => Ok(MetadataSummary::Unsigned(u64::from_le_bytes(
                self.read_hashed::<8>(hasher)?,
            ))),
            11 => Ok(MetadataSummary::Signed(i64::from_le_bytes(
                self.read_hashed::<8>(hasher)?,
            ))),
            12 => Ok(MetadataSummary::FloatBits(u64::from_le_bytes(
                self.read_hashed::<8>(hasher)?,
            ))),
            _ => Err(GgufError::InvalidMetadata("value type")),
        }
    }

    fn read_array_summary(
        &mut self,
        metadata_hasher: &mut blake3::Hasher,
    ) -> Result<MetadataSummary, GgufError> {
        let element_bytes = self.read_hashed::<4>(metadata_hasher)?;
        let element_type = u32::from_le_bytes(element_bytes);
        let count_bytes = self.read_hashed::<8>(metadata_hasher)?;
        let count = u64::from_le_bytes(count_bytes);
        if count > self.limits.max_array_elements {
            return Err(GgufError::LimitExceeded("array_elements"));
        }
        if element_type == 9 {
            return Err(GgufError::InvalidMetadata("nested array"));
        }
        let mut content = blake3::Hasher::new();
        content.update(b"NOOS/WWM/GGUF-ARRAY/V2");
        content.update(&element_bytes);
        content.update(&count_bytes);
        if element_type == 8 {
            for _ in 0..count {
                let length_bytes = self.read_hashed::<8>(metadata_hasher)?;
                content.update(&length_bytes);
                let length = u64::from_le_bytes(length_bytes);
                if length > self.limits.max_string_bytes {
                    return Err(GgufError::LimitExceeded("array_string_bytes"));
                }
                self.stream_hashed_bytes(
                    length,
                    metadata_hasher,
                    &mut content,
                    StreamValidation::Utf8,
                )?;
            }
        } else {
            let width = scalar_width(element_type)
                .ok_or(GgufError::InvalidMetadata("array element type"))?;
            let total = count.checked_mul(width).ok_or(GgufError::IntegerOverflow)?;
            let validation = if element_type == 7 {
                StreamValidation::Boolean
            } else {
                StreamValidation::None
            };
            self.stream_hashed_bytes(total, metadata_hasher, &mut content, validation)?;
        }
        Ok(MetadataSummary::Array {
            element_type,
            count,
            content_root: *content.finalize().as_bytes(),
        })
    }

    fn stream_hashed_bytes(
        &mut self,
        length: u64,
        first: &mut blake3::Hasher,
        second: &mut blake3::Hasher,
        validation: StreamValidation,
    ) -> Result<(), GgufError> {
        let mut remaining = length;
        let mut scratch = [0_u8; 65_536];
        let mut utf8_bytes = if validation == StreamValidation::Utf8 {
            Some(Vec::with_capacity(
                usize::try_from(length).map_err(|_| GgufError::IntegerOverflow)?,
            ))
        } else {
            None
        };
        while remaining != 0 {
            let chunk = usize::try_from(remaining.min(scratch.len() as u64))
                .map_err(|_| GgufError::IntegerOverflow)?;
            self.reader.read_exact(&mut scratch[..chunk])?;
            if validation == StreamValidation::Boolean
                && scratch[..chunk].iter().any(|value| *value > 1)
            {
                return Err(GgufError::InvalidMetadata("boolean array"));
            }
            first.update(&scratch[..chunk]);
            second.update(&scratch[..chunk]);
            if let Some(bytes) = utf8_bytes.as_mut() {
                bytes.extend_from_slice(&scratch[..chunk]);
            }
            remaining -= u64::try_from(chunk).map_err(|_| GgufError::IntegerOverflow)?;
        }
        if let Some(bytes) = utf8_bytes {
            std::str::from_utf8(&bytes).map_err(|_| GgufError::InvalidUtf8)?;
        }
        Ok(())
    }

    fn read_hashed<const N: usize>(
        &mut self,
        hasher: &mut blake3::Hasher,
    ) -> Result<[u8; N], GgufError> {
        let bytes = self.read_array::<N>()?;
        hasher.update(&bytes);
        Ok(bytes)
    }

    fn read_hashed_bounded_bytes(
        &mut self,
        maximum: u64,
        hasher: &mut blake3::Hasher,
    ) -> Result<Vec<u8>, GgufError> {
        let length_bytes = self.read_hashed::<8>(hasher)?;
        let length = u64::from_le_bytes(length_bytes);
        if length > maximum {
            return Err(GgufError::LimitExceeded("string_bytes"));
        }
        let bytes = self.read_exact_vec(length)?;
        hasher.update(&bytes);
        Ok(bytes)
    }

    fn read_bounded_bytes(&mut self, maximum: u64) -> Result<Vec<u8>, GgufError> {
        let length = self.read_u64()?;
        if length > maximum {
            return Err(GgufError::LimitExceeded("name_bytes"));
        }
        self.read_exact_vec(length)
    }

    fn read_exact_vec(&mut self, length: u64) -> Result<Vec<u8>, GgufError> {
        let mut bytes = vec![0; usize::try_from(length).map_err(|_| GgufError::IntegerOverflow)?];
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], GgufError> {
        let mut bytes = [0; N];
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn read_u32(&mut self) -> Result<u32, GgufError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, GgufError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn check_header_limit(&mut self) -> Result<(), GgufError> {
        if self.reader.stream_position()? > self.limits.max_header_bytes {
            return Err(GgufError::LimitExceeded("header_bytes"));
        }
        Ok(())
    }
}

fn tensor_byte_length(ggml_type: u32, dimensions: &[u64]) -> Result<u64, GgufError> {
    let first = *dimensions
        .first()
        .ok_or(GgufError::InvalidTensor("missing dimension"))?;
    let rows = dimensions
        .iter()
        .skip(1)
        .try_fold(1_u64, |product, dimension| {
            product
                .checked_mul(*dimension)
                .ok_or(GgufError::IntegerOverflow)
        })?;
    match ggml_type {
        F32_TYPE => first
            .checked_mul(rows)
            .and_then(|elements| elements.checked_mul(4))
            .ok_or(GgufError::IntegerOverflow),
        Q1_0_TYPE => {
            if first % Q1_0_BLOCK_ELEMENTS != 0 {
                return Err(GgufError::UnsupportedQuantization);
            }
            first
                .checked_div(Q1_0_BLOCK_ELEMENTS)
                .and_then(|blocks| blocks.checked_mul(Q1_0_BLOCK_BYTES))
                .and_then(|row_bytes| row_bytes.checked_mul(rows))
                .ok_or(GgufError::IntegerOverflow)
        }
        value => Err(GgufError::UnsupportedTensorType(value)),
    }
}

fn scalar_width(value_type: u32) -> Option<u64> {
    match value_type {
        0 | 1 | 7 => Some(1),
        2 | 3 => Some(2),
        4 | 5 | 6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    }
}

fn align_up(value: u64, alignment: u64) -> Result<u64, GgufError> {
    value
        .checked_add(alignment.checked_sub(1).ok_or(GgufError::IntegerOverflow)?)
        .map(|rounded| rounded / alignment * alignment)
        .ok_or(GgufError::IntegerOverflow)
}

fn required_u64(
    metadata: &BTreeMap<String, MetadataSummary>,
    key: &'static str,
) -> Result<u64, GgufError> {
    metadata
        .get(key)
        .and_then(MetadataSummary::as_u64)
        .ok_or(GgufError::InvalidMetadata(key))
}

fn required_text<'a>(
    metadata: &'a BTreeMap<String, MetadataSummary>,
    key: &'static str,
) -> Result<&'a str, GgufError> {
    metadata
        .get(key)
        .and_then(MetadataSummary::as_text)
        .ok_or(GgufError::InvalidMetadata(key))
}

fn required_array(
    metadata: &BTreeMap<String, MetadataSummary>,
    key: &'static str,
) -> Result<(u32, u64), GgufError> {
    metadata
        .get(key)
        .and_then(MetadataSummary::array)
        .ok_or(GgufError::InvalidMetadata(key))
}

fn required_token_id(
    metadata: &BTreeMap<String, MetadataSummary>,
    key: &'static str,
    token_count: u64,
) -> Result<u32, GgufError> {
    let value = required_u64(metadata, key)?;
    if value >= token_count {
        return Err(GgufError::InvalidMetadata(key));
    }
    u32::try_from(value).map_err(|_| GgufError::InvalidMetadata(key))
}

#[must_use]
pub fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn put_string(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&u64::try_from(value.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }

    fn put_u32_metadata(bytes: &mut Vec<u8>, key: &str, value: u32) {
        put_string(bytes, key);
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn put_bool_metadata(bytes: &mut Vec<u8>, key: &str, value: bool) {
        put_string(bytes, key);
        bytes.extend_from_slice(&7_u32.to_le_bytes());
        bytes.push(u8::from(value));
    }

    fn put_text_metadata(bytes: &mut Vec<u8>, key: &str, value: &str) {
        put_string(bytes, key);
        bytes.extend_from_slice(&8_u32.to_le_bytes());
        put_string(bytes, value);
    }

    fn put_string_array(bytes: &mut Vec<u8>, key: &str, values: &[&str]) {
        put_string(bytes, key);
        bytes.extend_from_slice(&9_u32.to_le_bytes());
        bytes.extend_from_slice(&8_u32.to_le_bytes());
        bytes.extend_from_slice(&u64::try_from(values.len()).unwrap().to_le_bytes());
        for value in values {
            put_string(bytes, value);
        }
    }

    fn put_i32_array(bytes: &mut Vec<u8>, key: &str, values: &[i32]) {
        put_string(bytes, key);
        bytes.extend_from_slice(&9_u32.to_le_bytes());
        bytes.extend_from_slice(&5_u32.to_le_bytes());
        bytes.extend_from_slice(&u64::try_from(values.len()).unwrap().to_le_bytes());
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }

    fn fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"GGUF");
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u64.to_le_bytes());
        bytes.extend_from_slice(&14_u64.to_le_bytes());
        put_text_metadata(&mut bytes, "general.architecture", "qwen35");
        put_text_metadata(&mut bytes, "general.name", "fixture");
        put_u32_metadata(&mut bytes, "general.quantization_version", 2);
        put_u32_metadata(&mut bytes, "general.file_type", 40);
        put_u32_metadata(&mut bytes, "qwen35.context_length", 4096);
        put_text_metadata(&mut bytes, "tokenizer.ggml.model", "gpt2");
        put_text_metadata(&mut bytes, "tokenizer.ggml.pre", "qwen35");
        put_string_array(&mut bytes, "tokenizer.ggml.tokens", &["a", "b", "c"]);
        put_i32_array(&mut bytes, "tokenizer.ggml.token_type", &[1, 1, 1]);
        put_string_array(&mut bytes, "tokenizer.ggml.merges", &["a b"]);
        put_u32_metadata(&mut bytes, "tokenizer.ggml.bos_token_id", 0);
        put_u32_metadata(&mut bytes, "tokenizer.ggml.eos_token_id", 1);
        put_u32_metadata(&mut bytes, "tokenizer.ggml.padding_token_id", 2);
        put_bool_metadata(&mut bytes, "tokenizer.ggml.add_bos_token", false);
        // Replace the last count by adding the required template metadata.
        let metadata_count_offset = 16;
        bytes[metadata_count_offset..metadata_count_offset + 8]
            .copy_from_slice(&15_u64.to_le_bytes());
        put_text_metadata(&mut bytes, "tokenizer.chat_template", "{{ message }}");

        put_string(&mut bytes, "weight");
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&128_u64.to_le_bytes());
        bytes.extend_from_slice(&2_u64.to_le_bytes());
        bytes.extend_from_slice(&Q1_0_TYPE.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        put_string(&mut bytes, "norm");
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&8_u64.to_le_bytes());
        bytes.extend_from_slice(&F32_TYPE.to_le_bytes());
        bytes.extend_from_slice(&64_u64.to_le_bytes());
        while bytes.len() % 32 != 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(&[0; 36]);
        bytes.extend_from_slice(&[0; 28]);
        bytes.extend_from_slice(&[0; 32]);
        bytes
    }

    fn verified(bytes: &[u8]) -> VerifiedStream {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        VerifiedStream {
            byte_length: u64::try_from(bytes.len()).unwrap(),
            sha256: digest,
        }
    }

    #[test]
    fn bounded_fixture_inspects_without_retaining_payload() {
        let bytes = fixture();
        let inspection =
            inspect_gguf(Cursor::new(&bytes), verified(&bytes), GgufLimits::default()).unwrap();
        assert_eq!(inspection.architecture, "qwen35");
        assert_eq!(inspection.q1_tensor_count, 1);
        assert_eq!(inspection.f32_tensor_count, 1);
        assert!(inspection.retained_bytes_upper_bound() < bytes.len());
    }

    #[test]
    fn stream_verifier_rejects_mutation_truncation_and_extension() {
        let bytes = fixture();
        let expected = verified(&bytes);
        assert_eq!(
            stream_verify(Cursor::new(&bytes), expected.byte_length, expected.sha256).unwrap(),
            expected
        );
        let mut mutated = bytes.clone();
        let index = mutated.len() - 1;
        mutated[index] ^= 1;
        assert!(matches!(
            stream_verify(Cursor::new(mutated), expected.byte_length, expected.sha256),
            Err(GgufError::Sha256Mismatch { .. })
        ));
        assert!(matches!(
            stream_verify(
                Cursor::new(&bytes[..bytes.len() - 1]),
                expected.byte_length,
                expected.sha256
            ),
            Err(GgufError::LengthMismatch { .. })
        ));
        let mut extended = bytes;
        extended.push(0);
        assert!(matches!(
            stream_verify(Cursor::new(extended), expected.byte_length, expected.sha256),
            Err(GgufError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_overlap_ambiguous_and_unsupported_q1_semantics_reject() {
        let bytes = fixture();
        let bos = b"tokenizer.ggml.bos_token_id";
        let eos = b"tokenizer.ggml.eos_token_id";
        assert_eq!(bos.len(), eos.len());
        let position = bytes
            .windows(bos.len())
            .position(|window| window == bos)
            .unwrap();
        let mut duplicate = bytes.clone();
        duplicate[position..position + bos.len()].copy_from_slice(eos);
        assert!(matches!(
            inspect_gguf(
                Cursor::new(&duplicate),
                verified(&duplicate),
                GgufLimits::default()
            ),
            Err(GgufError::DuplicateMetadata(_))
        ));

        let mut unsupported = bytes.clone();
        let weight = b"weight";
        let weight_name = unsupported
            .windows(weight.len())
            .rposition(|window| window == weight)
            .unwrap();
        let weight_type = weight_name + weight.len() + 4 + 16;
        unsupported[weight_type..weight_type + 4].copy_from_slice(&42_u32.to_le_bytes());
        assert!(matches!(
            inspect_gguf(
                Cursor::new(&unsupported),
                verified(&unsupported),
                GgufLimits::default()
            ),
            Err(GgufError::UnsupportedTensorType(42))
        ));

        let mut overlap = bytes.clone();
        let norm = b"norm";
        let norm_name = overlap
            .windows(norm.len())
            .rposition(|window| window == norm)
            .unwrap();
        let norm_offset = norm_name + norm.len() + 4 + 8 + 4;
        overlap[norm_offset..norm_offset + 8].copy_from_slice(&32_u64.to_le_bytes());
        assert!(matches!(
            inspect_gguf(
                Cursor::new(&overlap),
                verified(&overlap),
                GgufLimits::default()
            ),
            Err(GgufError::TensorOverlap)
        ));

        let mut ambiguous = bytes;
        let bos_position = ambiguous
            .windows(bos.len())
            .position(|window| window == bos)
            .unwrap();
        let bos_value = bos_position + bos.len() + 4;
        ambiguous[bos_value..bos_value + 4].copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            inspect_gguf(
                Cursor::new(&ambiguous),
                verified(&ambiguous),
                GgufLimits::default()
            ),
            Err(GgufError::InvalidMetadata("tokenizer.ggml.bos_token_id"))
        ));
    }
}
