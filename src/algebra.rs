//! Scalar and group types.

use core::fmt;
use core::ops::{Add, Mul, Sub};

use k256::elliptic_curve::group::prime::PrimeCurveAffine as _;
use k256::elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _};
use k256::{AffinePoint, ProjectivePoint};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// A secp256k1 scalar.
pub use k256::Scalar;

/// A group element, including the identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Element(ProjectivePoint);

impl Element {
    /// The group identity.
    pub const IDENTITY: Self = Self(ProjectivePoint::IDENTITY);

    /// The group generator.
    pub const GENERATOR: Self = Self(ProjectivePoint::GENERATOR);

    /// Creates an element from a projective point.
    #[must_use]
    pub const fn new(point: ProjectivePoint) -> Self {
        Self(point)
    }

    /// Multiplies the generator by `scalar`.
    #[must_use]
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self(ProjectivePoint::GENERATOR * scalar)
    }

    /// Returns the projective point.
    #[must_use]
    pub const fn as_projective(&self) -> &ProjectivePoint {
        &self.0
    }

    /// Returns true for the group identity.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.0 == ProjectivePoint::IDENTITY
    }

    /// Encodes the element as a tagged 34-byte value.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 34] {
        let mut bytes = [0_u8; 34];
        if self.is_identity() {
            return bytes;
        }

        bytes[0] = 1;
        bytes[1..].copy_from_slice(self.0.to_affine().to_encoded_point(true).as_bytes());
        bytes
    }

    /// Decodes a tagged 34-byte element.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown tag, nonzero identity padding, or an
    /// invalid point.
    pub fn from_bytes(bytes: &[u8; 34]) -> Result<Self> {
        match bytes[0] {
            0 if bytes[1..].iter().all(|byte| *byte == 0) => Ok(Self::IDENTITY),
            0 => Err(Error::InvalidIdentity),
            1 => {
                let point = bytes[1..].try_into().map_err(|_| Error::InvalidPoint)?;
                Point::from_bytes(point).map(Into::into)
            }
            _ => Err(Error::InvalidElementTag),
        }
    }
}

impl Add for Element {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Element {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul<Scalar> for Element {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl fmt::Debug for Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Element").field(&self.to_bytes()).finish()
    }
}

/// A nonidentity group element.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Point(ProjectivePoint);

impl Point {
    /// Creates a point from a projective point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IdentityPoint`] for the identity.
    pub fn new(point: ProjectivePoint) -> Result<Self> {
        if point == ProjectivePoint::IDENTITY {
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
    pub fn from_scalar(scalar: Scalar) -> Result<Self> {
        Self::new(ProjectivePoint::GENERATOR * scalar)
    }

    /// Returns the projective point.
    #[must_use]
    pub const fn as_projective(&self) -> &ProjectivePoint {
        &self.0
    }

    /// Encodes the point in compressed SEC1 form.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 33] {
        let encoded = self.0.to_affine().to_encoded_point(true);
        let mut bytes = [0_u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    /// Decodes a compressed SEC1 point.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input or the identity.
    pub fn from_bytes(bytes: &[u8; 33]) -> Result<Self> {
        let encoded = k256::EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or(Error::InvalidPoint)?;
        if bool::from(affine.is_identity()) {
            return Err(Error::IdentityPoint);
        }
        Ok(Self(ProjectivePoint::from(affine)))
    }
}

impl From<Point> for Element {
    fn from(point: Point) -> Self {
        Self(point.0)
    }
}

impl TryFrom<Element> for Point {
    type Error = Error;

    fn try_from(element: Element) -> Result<Self> {
        Self::new(element.0)
    }
}

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Point").field(&self.to_bytes()).finish()
    }
}

/// An owned scalar that clears itself on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar(Scalar);

impl SecretScalar {
    /// Wraps a scalar as secret state.
    #[must_use]
    pub const fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    /// Borrows the scalar for one operation.
    pub fn expose<T>(&self, use_scalar: impl FnOnce(&Scalar) -> T) -> T {
        use_scalar(&self.0)
    }
}

impl fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretScalar([REDACTED])")
    }
}
