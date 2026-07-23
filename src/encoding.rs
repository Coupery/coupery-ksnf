//! Canonical protocol encoding.

use k256::elliptic_curve::PrimeField as _;

use crate::algebra::{Element, Point, Scalar};
use crate::{Error, Result};

/// A canonical byte writer.
#[derive(Default)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    /// Creates an empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends one byte.
    pub fn put_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends a big-endian `u16`.
    pub fn put_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u32`.
    pub fn put_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u64`.
    pub fn put_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a fixed-size field.
    pub fn put_fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    /// Appends a `u32`-length-prefixed byte string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when `value` exceeds `u32::MAX`.
    pub fn put_bytes(&mut self, value: &[u8]) -> Result<()> {
        let len = u32::try_from(value.len()).map_err(|_| Error::LengthOverflow)?;
        self.put_u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Appends a canonical scalar.
    pub fn put_scalar(&mut self, scalar: &Scalar) {
        self.put_fixed(&scalar.to_bytes().into());
    }

    /// Appends a compressed nonidentity point.
    pub fn put_point(&mut self, point: Point) {
        self.put_fixed(&point.to_bytes());
    }

    /// Appends a tagged group element.
    pub fn put_element(&mut self, element: Element) {
        self.put_fixed(&element.to_bytes());
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// A canonical byte reader.
pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

#[allow(clippy::missing_errors_doc)]
impl<'a> Decoder<'a> {
    /// Creates a reader over `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Reads one byte.
    pub fn get_u8(&mut self) -> Result<u8> {
        Ok(self.read::<1>()?[0])
    }

    /// Reads a big-endian `u16`.
    pub fn get_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read()?))
    }

    /// Reads a big-endian `u32`.
    pub fn get_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read()?))
    }

    /// Reads a big-endian `u64`.
    pub fn get_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read()?))
    }

    /// Reads a fixed-size field.
    pub fn get_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.read()
    }

    /// Reads a `u32`-length-prefixed byte string.
    pub fn get_bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.get_u32()?).map_err(|_| Error::LengthOverflow)?;
        let start = self.offset;
        let end = start.checked_add(len).ok_or(Error::LengthOverflow)?;
        let bytes = self.input.get(start..end).ok_or(Error::UnexpectedEnd {
            offset: start,
            needed: len,
        })?;
        self.offset = end;
        Ok(bytes)
    }

    /// Reads a canonical scalar.
    pub fn get_scalar(&mut self) -> Result<Scalar> {
        let bytes = self.read::<32>()?;
        Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or(Error::InvalidScalar)
    }

    /// Reads a compressed nonidentity point.
    pub fn get_point(&mut self) -> Result<Point> {
        Point::from_bytes(&self.read()?)
    }

    /// Reads a tagged group element.
    pub fn get_element(&mut self) -> Result<Element> {
        Element::from_bytes(&self.read()?)
    }

    /// Succeeds when no bytes remain.
    pub const fn finish(self) -> Result<()> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes {
                offset: self.offset,
            })
        }
    }

    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        let start = self.offset;
        let end = start.checked_add(N).ok_or(Error::LengthOverflow)?;
        let bytes = self.input.get(start..end).ok_or(Error::UnexpectedEnd {
            offset: start,
            needed: N,
        })?;
        self.offset = end;
        bytes.try_into().map_err(|_| Error::UnexpectedEnd {
            offset: start,
            needed: N,
        })
    }
}
