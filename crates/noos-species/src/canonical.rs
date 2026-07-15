use crate::{Hash32, SpeciesError};

pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(domain: &str) -> Self {
        let mut value = Self { bytes: Vec::new() };
        value.bytes(domain.as_bytes());
        value
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn hash(&mut self, value: &Hash32) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub(crate) fn hashes(&mut self, values: &[Hash32]) {
        self.u32(u32::try_from(values.len()).unwrap_or(u32::MAX));
        for value in values {
            self.hash(value);
        }
    }

    pub(crate) fn optional_hash(&mut self, value: Option<&Hash32>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.hash(value);
            }
            None => self.u8(0),
        }
    }

    pub(crate) fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
            None => self.u8(0),
        }
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], domain: &str) -> Result<Self, SpeciesError> {
        let mut decoder = Self { bytes, cursor: 0 };
        if decoder.bytes()? != domain.as_bytes() {
            return Err(SpeciesError::UnknownEncoding);
        }
        Ok(decoder)
    }

    pub(crate) fn finish(self) -> Result<(), SpeciesError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(SpeciesError::NonCanonicalEncoding)
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], SpeciesError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(SpeciesError::MalformedEncoding)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SpeciesError::MalformedEncoding)?;
        self.cursor = end;
        slice
            .try_into()
            .map_err(|_| SpeciesError::MalformedEncoding)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, SpeciesError> {
        Ok(self.take::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, SpeciesError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, SpeciesError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    pub(crate) fn hash(&mut self) -> Result<Hash32, SpeciesError> {
        self.take()
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], SpeciesError> {
        let length = usize::try_from(self.u32()?).map_err(|_| SpeciesError::MalformedEncoding)?;
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SpeciesError::MalformedEncoding)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SpeciesError::MalformedEncoding)?;
        self.cursor = end;
        Ok(value)
    }

    pub(crate) fn hashes(&mut self) -> Result<Vec<Hash32>, SpeciesError> {
        let length = usize::try_from(self.u32()?).map_err(|_| SpeciesError::MalformedEncoding)?;
        let byte_length = length
            .checked_mul(32)
            .ok_or(SpeciesError::MalformedEncoding)?;
        if byte_length > self.bytes.len().saturating_sub(self.cursor) {
            return Err(SpeciesError::MalformedEncoding);
        }
        (0..length).map(|_| self.hash()).collect()
    }

    pub(crate) fn optional_hash(&mut self) -> Result<Option<Hash32>, SpeciesError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.hash()?)),
            _ => Err(SpeciesError::NonCanonicalEncoding),
        }
    }

    pub(crate) fn optional_u64(&mut self) -> Result<Option<u64>, SpeciesError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(SpeciesError::NonCanonicalEncoding),
        }
    }
}

pub(crate) fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
