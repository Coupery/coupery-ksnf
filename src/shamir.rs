//! Shamir polynomial operations.

use k256::elliptic_curve::Field as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algebra::{Element, Scalar, SecretScalar};
use crate::{Error, Result};

/// A nonzero Shamir evaluation node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node(Scalar);

impl Node {
    /// Creates a nonzero node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNode`] for zero.
    pub fn new(value: Scalar) -> Result<Self> {
        if value == Scalar::ZERO {
            Err(Error::ZeroNode)
        } else {
            Ok(Self(value))
        }
    }

    /// Creates a node from a nonzero integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNode`] for zero.
    pub fn from_u64(value: u64) -> Result<Self> {
        Self::new(Scalar::from(value))
    }

    /// Returns the scalar value.
    #[must_use]
    pub const fn scalar(self) -> Scalar {
        self.0
    }
}

/// A secret polynomial with at least one coefficient.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Creates a polynomial in constant-first order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyInput`] when no coefficients are supplied.
    pub fn new(coefficients: Vec<Scalar>) -> Result<Self> {
        if coefficients.is_empty() {
            Err(Error::EmptyInput)
        } else {
            Ok(Self { coefficients })
        }
    }

    /// Samples a degree-bounded polynomial with the given constant.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyInput`] when `threshold` is zero.
    pub fn sample(
        threshold: usize,
        constant: &SecretScalar,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<Self> {
        if threshold == 0 {
            return Err(Error::EmptyInput);
        }

        let mut coefficients = Vec::with_capacity(threshold);
        constant.expose(|value| coefficients.push(*value));
        coefficients.extend((1..threshold).map(|_| Scalar::random(&mut *rng)));
        Self::new(coefficients)
    }

    /// Returns the number of coefficients.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    /// Returns false because a polynomial always has a coefficient.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Evaluates the polynomial at `node`.
    #[must_use]
    pub fn evaluate(&self, node: Node) -> SecretScalar {
        let value = self
            .coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, coefficient| acc * node.0 + coefficient);
        SecretScalar::new(value)
    }

    /// Returns the coefficient commitments.
    #[must_use]
    pub fn commitments(&self) -> Vec<Element> {
        self.coefficients
            .iter()
            .map(|coefficient| Element::from_scalar(*coefficient))
            .collect()
    }
}

/// Computes the Lagrange row at zero for `nodes`.
///
/// # Errors
///
/// Returns an error for an empty support or duplicate node.
pub fn lagrange_at_zero(nodes: &[Node]) -> Result<Vec<Scalar>> {
    validate_support(nodes)?;

    let mut row = Vec::with_capacity(nodes.len());
    for (i, node_i) in nodes.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, node_j) in nodes.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator *= -node_j.0;
            denominator *= node_i.0 - node_j.0;
        }
        let inverse = Option::<Scalar>::from(denominator.invert()).ok_or(Error::DuplicateNode)?;
        row.push(numerator * inverse);
    }
    Ok(row)
}

/// Reconstructs a sharing's constant from one accepted support.
///
/// # Errors
///
/// Returns an error for mismatched lengths or an invalid support.
pub fn interpolate_constant(nodes: &[Node], values: &[Scalar]) -> Result<Scalar> {
    if nodes.len() != values.len() {
        return Err(Error::LengthMismatch);
    }
    let row = lagrange_at_zero(nodes)?;
    Ok(row
        .iter()
        .zip(values)
        .fold(Scalar::ZERO, |sum, (coefficient, value)| {
            sum + coefficient * value
        }))
}

fn validate_support(nodes: &[Node]) -> Result<()> {
    if nodes.is_empty() {
        return Err(Error::EmptyInput);
    }
    for (i, node) in nodes.iter().enumerate() {
        if nodes[..i].contains(node) {
            return Err(Error::DuplicateNode);
        }
    }
    Ok(())
}
