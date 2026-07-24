//! Canonical protocol encoding.

use core::marker::PhantomData;

use frost_core::{Field, Group};

use crate::algebra::{Element, Point, ScalarFor};
#[cfg(all(feature = "secp256k1", any(test, feature = "taproot")))]
use crate::profile::Secp256k1;
use crate::profile::{DefaultProfile, Profile, ScalarBytes};
use crate::{Error, Result};

type FieldOf<P> = <<P as Profile>::Group as Group>::Field;

/// A canonical byte writer.
pub struct Encoder<P: Profile = DefaultProfile> {
    bytes: Vec<u8>,
    profile: PhantomData<P>,
}

impl<P: Profile> Encoder<P> {
    /// Creates an empty writer for `P`.
    #[must_use]
    pub const fn for_profile() -> Self {
        Self {
            bytes: Vec::new(),
            profile: PhantomData,
        }
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
    pub fn put_scalar(&mut self, scalar: &ScalarFor<P>) {
        self.bytes
            .extend_from_slice(FieldOf::<P>::serialize(scalar).as_ref());
    }

    /// Appends a canonical nonidentity point.
    pub fn put_point(&mut self, point: Point<P>) {
        self.bytes.extend_from_slice(point.to_bytes().as_ref());
    }

    /// Appends a tagged group element.
    pub fn put_element(&mut self, element: Element<P>) {
        self.bytes.extend_from_slice(&element.to_bytes());
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(all(feature = "secp256k1", any(test, feature = "taproot")))]
impl Encoder<Secp256k1> {
    /// Creates an empty secp256k1 writer.
    #[must_use]
    pub const fn new() -> Self {
        Self::for_profile()
    }
}

impl<P: Profile> Default for Encoder<P> {
    fn default() -> Self {
        Self::for_profile()
    }
}

/// A canonical byte reader.
pub struct Decoder<'a, P: Profile = DefaultProfile> {
    input: &'a [u8],
    offset: usize,
    profile: PhantomData<P>,
}

impl<'a, P: Profile> Decoder<'a, P> {
    /// Creates a reader over `input` for `P`.
    #[must_use]
    pub const fn for_profile(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            profile: PhantomData,
        }
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is too short.
    pub fn get_u8(&mut self) -> Result<u8> {
        Ok(self.read::<1>()?[0])
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is too short.
    pub fn get_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read()?))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is too short.
    pub fn get_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read()?))
    }

    /// Reads a big-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is too short.
    pub fn get_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read()?))
    }

    /// Reads a fixed-size field.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is too short.
    pub fn get_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.read()
    }

    /// Reads a `u32`-length-prefixed byte string.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid length or short input.
    pub fn get_bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.get_u32()?).map_err(|_| Error::LengthOverflow)?;
        self.read_slice(len)
    }

    /// Reads a canonical scalar.
    ///
    /// # Errors
    ///
    /// Returns an error for short input or a noncanonical scalar.
    pub fn get_scalar(&mut self) -> Result<ScalarFor<P>> {
        let len = FieldOf::<P>::serialize(&FieldOf::<P>::zero())
            .as_ref()
            .len();
        let bytes = self.read_slice(len)?;
        let encoded = ScalarBytes::<P>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        FieldOf::<P>::deserialize(&encoded).map_err(|_| Error::InvalidScalar)
    }

    /// Reads a canonical nonidentity point.
    ///
    /// # Errors
    ///
    /// Returns an error for short or invalid input.
    pub fn get_point(&mut self) -> Result<Point<P>> {
        let len = P::encode_point(&P::Group::generator()).as_ref().len();
        Point::from_bytes(self.read_slice(len)?)
    }

    /// Reads a tagged group element.
    ///
    /// # Errors
    ///
    /// Returns an error for short or invalid input.
    pub fn get_element(&mut self) -> Result<Element<P>> {
        let len = P::encode_point(&P::Group::generator()).as_ref().len() + 1;
        Element::from_bytes(self.read_slice(len)?)
    }

    /// Succeeds when no bytes remain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TrailingBytes`] when bytes remain.
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
        self.read_slice(N)?
            .try_into()
            .map_err(|_| Error::UnexpectedEnd {
                offset: self.offset,
                needed: N,
            })
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let start = self.offset;
        let end = start.checked_add(len).ok_or(Error::LengthOverflow)?;
        let bytes = self.input.get(start..end).ok_or(Error::UnexpectedEnd {
            offset: start,
            needed: len,
        })?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(all(feature = "secp256k1", any(test, feature = "taproot")))]
impl<'a> Decoder<'a, Secp256k1> {
    /// Creates a secp256k1 reader over `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self::for_profile(input)
    }
}

#[cfg(all(test, feature = "secp256k1"))]
mod tests {
    use super::{Decoder, Encoder};
    use crate::algebra::{Point, Scalar};
    use crate::{Error, Result};

    #[test]
    fn rejects_truncation_and_trailing_bytes() -> Result<()> {
        let scalar = Scalar::from(9_u64);
        let point = Point::from_scalar(Scalar::from(11_u64))?;
        let mut encoder = Encoder::new();
        encoder.put_u8(1);
        encoder.put_bytes(b"ksnf")?;
        encoder.put_scalar(&scalar);
        encoder.put_point(point);
        let bytes = encoder.finish();

        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.get_u8()?, 1);
        assert_eq!(decoder.get_bytes()?, b"ksnf");
        assert_eq!(decoder.get_scalar()?, scalar);
        assert_eq!(decoder.get_point()?, point);
        decoder.finish()?;

        let mut truncated = Decoder::new(&bytes[..bytes.len() - 1]);
        assert_eq!(truncated.get_u8()?, 1);
        assert_eq!(truncated.get_bytes()?, b"ksnf");
        assert_eq!(truncated.get_scalar()?, scalar);
        assert!(matches!(
            truncated.get_point(),
            Err(Error::UnexpectedEnd { .. })
        ));

        let mut with_trailer = bytes;
        with_trailer.push(0);
        let mut decoder = Decoder::new(&with_trailer);
        assert_eq!(decoder.get_u8()?, 1);
        assert_eq!(decoder.get_bytes()?, b"ksnf");
        assert_eq!(decoder.get_scalar()?, scalar);
        assert_eq!(decoder.get_point()?, point);
        assert!(matches!(decoder.finish(), Err(Error::TrailingBytes { .. })));
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_scalars() {
        let mut decoder = Decoder::new(&[0xff; 32]);
        assert_eq!(decoder.get_scalar(), Err(Error::InvalidScalar));
    }
}
