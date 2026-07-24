//! Scalars and group elements.

use core::fmt;
use core::ops::{Add, Mul, Sub};

use frost_core::Group as _;

use crate::profile::{DefaultProfile, PointBytes, Profile, RawElement};
use crate::{Error, Result};

#[cfg(feature = "secp256k1")]
pub use k256::Scalar;

/// A scalar in profile `P`.
pub type ScalarFor<P> = crate::profile::Scalar<P>;

/// A group element, including the identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Element<P: Profile = DefaultProfile>(RawElement<P>);

impl<P: Profile> Element<P> {
    /// Returns the group identity.
    #[must_use]
    pub fn identity() -> Self {
        Self(P::Group::identity())
    }

    /// Returns the group generator.
    #[must_use]
    pub fn generator() -> Self {
        Self(P::Group::generator())
    }

    /// Wraps a raw group element.
    #[must_use]
    pub const fn new(point: RawElement<P>) -> Self {
        Self(point)
    }

    /// Multiplies the generator by `scalar`.
    #[must_use]
    pub fn from_scalar(scalar: ScalarFor<P>) -> Self {
        Self(P::Group::generator() * scalar)
    }

    /// Returns the raw group element.
    #[must_use]
    pub const fn as_raw(&self) -> &RawElement<P> {
        &self.0
    }

    /// Returns true for the group identity.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.0 == P::Group::identity()
    }

    /// Encodes the element with an explicit identity tag.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let point_len = P::encode_point(&P::Group::generator()).as_ref().len();
        let mut bytes = vec![0_u8; point_len + 1];
        if self.is_identity() {
            return bytes;
        }
        let point = P::encode_point(&self.0);
        bytes[0] = 1;
        bytes[1..].copy_from_slice(point.as_ref());
        bytes
    }

    /// Decodes an identity-tagged element.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong length, an unknown tag, nonzero identity
    /// padding, or an invalid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let point_len = P::encode_point(&P::Group::generator()).as_ref().len();
        if bytes.len() != point_len + 1 {
            return Err(Error::LengthMismatch);
        }
        match bytes[0] {
            0 if bytes[1..].iter().all(|byte| *byte == 0) => Ok(Self::identity()),
            0 => Err(Error::InvalidIdentity),
            1 => Point::<P>::from_bytes(&bytes[1..]).map(Into::into),
            _ => Err(Error::InvalidElementTag),
        }
    }
}

impl<P: Profile> Add for Element<P> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<P: Profile> Sub for Element<P> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<P: Profile> Mul<ScalarFor<P>> for Element<P> {
    type Output = Self;

    fn mul(self, rhs: ScalarFor<P>) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl<P: Profile> fmt::Debug for Element<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Element")
            .field(&self.to_bytes())
            .finish()
    }
}

/// A nonidentity group element.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Point<P: Profile = DefaultProfile>(RawElement<P>);

impl<P: Profile> Point<P> {
    /// Wraps a nonidentity raw point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IdentityPoint`] for the identity.
    pub fn new(point: RawElement<P>) -> Result<Self> {
        if point == P::Group::identity() {
            Err(Error::IdentityPoint)
        } else {
            Ok(Self(point))
        }
    }

    /// Multiplies the generator by a nonzero scalar.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IdentityPoint`] for zero.
    pub fn from_scalar(scalar: ScalarFor<P>) -> Result<Self> {
        Self::new(P::Group::generator() * scalar)
    }

    /// Returns the raw group element.
    #[must_use]
    pub const fn as_raw(&self) -> &RawElement<P> {
        &self.0
    }

    /// Returns the canonical point encoding.
    #[must_use]
    pub fn to_bytes(self) -> PointBytes<P> {
        P::encode_point(&self.0)
    }

    /// Decodes a canonical nonidentity point.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, identity, torsion, or
    /// non-prime-subgroup input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = PointBytes::<P>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        let point = P::Group::deserialize(&encoded).map_err(|error| match error {
            frost_core::GroupError::InvalidIdentityElement => Error::IdentityPoint,
            _ => Error::InvalidPoint,
        })?;
        Self::new(point)
    }
}

impl<P: Profile> From<Point<P>> for Element<P> {
    fn from(point: Point<P>) -> Self {
        Self(point.0)
    }
}

impl<P: Profile> TryFrom<Element<P>> for Point<P> {
    type Error = Error;

    fn try_from(element: Element<P>) -> Result<Self> {
        Self::new(element.0)
    }
}

impl<P: Profile> fmt::Debug for Point<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Point")
            .field(&self.to_bytes().as_ref())
            .finish()
    }
}

/// An owned scalar that clears itself on drop.
pub struct SecretScalar<P: Profile = DefaultProfile>(ScalarFor<P>);

impl<P: Profile> SecretScalar<P> {
    /// Wraps a scalar as secret state.
    #[must_use]
    pub const fn new(scalar: ScalarFor<P>) -> Self {
        Self(scalar)
    }

    /// Borrows the scalar for one operation.
    pub fn expose<T>(&self, use_scalar: impl FnOnce(&ScalarFor<P>) -> T) -> T {
        use_scalar(&self.0)
    }
}

impl<P: Profile> Drop for SecretScalar<P> {
    fn drop(&mut self) {
        P::clear_scalar(&mut self.0);
    }
}

impl<P: Profile> fmt::Debug for SecretScalar<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretScalar([REDACTED])")
    }
}
