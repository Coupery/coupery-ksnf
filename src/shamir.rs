//! Shamir polynomial operations.

use core::fmt;

use frost_core::{Field, Group};

use crate::algebra::{Element, ScalarFor, SecretScalar};
use crate::profile::{DefaultProfile, Profile};
use crate::{Error, Result};

type FieldOf<P> = <<P as Profile>::Group as Group>::Field;

/// A nonzero Shamir evaluation node.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Node<P: Profile = DefaultProfile>(ScalarFor<P>);

impl<P: Profile> Node<P> {
    /// Creates a nonzero node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNode`] for zero.
    pub fn new(value: ScalarFor<P>) -> Result<Self> {
        if value == FieldOf::<P>::zero() {
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
        Self::new(P::scalar_from_u64(value))
    }

    /// Returns the scalar value.
    #[must_use]
    pub const fn scalar(self) -> ScalarFor<P> {
        self.0
    }
}

impl<P: Profile> fmt::Debug for Node<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Node")
            .field(&FieldOf::<P>::serialize(&self.0).as_ref())
            .finish()
    }
}

/// A secret polynomial with at least one coefficient.
pub struct Polynomial<P: Profile = DefaultProfile> {
    coefficients: Vec<ScalarFor<P>>,
}

impl<P: Profile> Polynomial<P> {
    /// Creates a polynomial in constant-first order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyInput`] when no coefficients are supplied.
    pub fn new(coefficients: Vec<ScalarFor<P>>) -> Result<Self> {
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
        constant: &SecretScalar<P>,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<Self> {
        if threshold == 0 {
            return Err(Error::EmptyInput);
        }

        let mut coefficients = Vec::with_capacity(threshold);
        constant.expose(|value| coefficients.push(*value));
        coefficients.extend((1..threshold).map(|_| FieldOf::<P>::random(&mut *rng)));
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
    pub fn evaluate(&self, node: Node<P>) -> SecretScalar<P> {
        let value = self
            .coefficients
            .iter()
            .rev()
            .fold(FieldOf::<P>::zero(), |acc, coefficient| {
                acc * node.0 + *coefficient
            });
        SecretScalar::new(value)
    }

    /// Returns the coefficient commitments.
    #[must_use]
    pub fn commitments(&self) -> Vec<Element<P>> {
        self.coefficients
            .iter()
            .map(|coefficient| Element::from_scalar(*coefficient))
            .collect()
    }
}

impl<P: Profile> Drop for Polynomial<P> {
    fn drop(&mut self) {
        for coefficient in &mut self.coefficients {
            P::clear_scalar(coefficient);
        }
    }
}

/// Computes the Lagrange row at zero for `nodes`.
///
/// # Errors
///
/// Returns an error for an empty support or duplicate node.
pub fn lagrange_at_zero<P: Profile>(nodes: &[Node<P>]) -> Result<Vec<ScalarFor<P>>> {
    validate_support(nodes)?;

    let mut row = Vec::with_capacity(nodes.len());
    for (i, node_i) in nodes.iter().enumerate() {
        let mut numerator = FieldOf::<P>::one();
        let mut denominator = FieldOf::<P>::one();
        for (j, node_j) in nodes.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = numerator * (FieldOf::<P>::zero() - node_j.0);
            denominator = denominator * (node_i.0 - node_j.0);
        }
        let inverse = FieldOf::<P>::invert(&denominator).map_err(|_| Error::DuplicateNode)?;
        row.push(numerator * inverse);
    }
    Ok(row)
}

/// Reconstructs a sharing's constant from one accepted support.
///
/// # Errors
///
/// Returns an error for mismatched lengths or an invalid support.
pub fn interpolate_constant<P: Profile>(
    nodes: &[Node<P>],
    values: &[ScalarFor<P>],
) -> Result<ScalarFor<P>> {
    if nodes.len() != values.len() {
        return Err(Error::LengthMismatch);
    }
    let row = lagrange_at_zero(nodes)?;
    Ok(row
        .iter()
        .zip(values)
        .fold(FieldOf::<P>::zero(), |sum, (coefficient, value)| {
            sum + *coefficient * *value
        }))
}

fn validate_support<P: Profile>(nodes: &[Node<P>]) -> Result<()> {
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
