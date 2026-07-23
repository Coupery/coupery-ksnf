//! Domain-separated hashes.

use k256::Scalar;
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, hash_to_field};
use sha2::Sha256;

use crate::{Error, Result};

/// A versioned hash domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Domain {
    /// Redistribution commitments.
    Deal,
    /// Private member records.
    Member,
    /// Nonce commitments.
    Nonce,
    /// FROST binding factors.
    Bind,
    /// Schnorr challenges.
    Challenge,
}

impl Domain {
    /// Returns the fixed domain bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Deal => b"KSNF/v1/deal",
            Self::Member => b"KSNF/v1/member",
            Self::Nonce => b"KSNF/v1/nonce",
            Self::Bind => b"KSNF/v1/bind",
            Self::Challenge => b"KSNF/v1/challenge",
        }
    }
}

/// Hashes `message` to a secp256k1 scalar in `domain`.
///
/// # Errors
///
/// Returns [`Error::HashToField`] if the fixed domain is rejected.
pub fn to_scalar(domain: Domain, message: &[u8]) -> Result<Scalar> {
    let mut output = [Scalar::ZERO];
    hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[message], &[domain.as_bytes()], &mut output)
        .map_err(|_| Error::HashToField)?;
    Ok(output[0])
}
