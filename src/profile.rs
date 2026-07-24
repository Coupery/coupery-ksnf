//! Curated protocol profiles.

use core::fmt;

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
use crate::Error;
use crate::Result;
use frost_core::{Field, Group};

mod private {
    pub trait Sealed {}
}

/// One reviewed KSNF group and byte profile.
///
/// This trait is sealed. New profiles require protocol vectors and a proof
/// mapping before they become part of the crate.
pub trait Profile: private::Sealed + Copy + Eq + fmt::Debug + Send + Sync + 'static {
    /// The profile's prime-order group.
    type Group: Group;

    /// The profile's final signature encoding.
    type SignatureBytes: AsRef<[u8]> + Copy + Eq + fmt::Debug;

    /// The leading byte on structured protocol objects.
    const WIRE_ID: u8;

    /// The identifier bound into root signing packages.
    const PROTOCOL_ID: &'static [u8];

    /// The immutable-material storage header.
    const MATERIAL_MAGIC: &'static [u8; 8];

    /// The journal storage header.
    const JOURNAL_MAGIC: &'static [u8; 8];

    /// Hashes one KSNF transcript preimage to a scalar.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile hash rejects its fixed domain.
    fn hash_to_scalar(domain: HashDomain, message: &[u8]) -> Result<Scalar<Self>>;

    /// Computes the final signature challenge.
    ///
    /// # Errors
    ///
    /// Returns an error when an input exceeds the profile's encoding limit.
    fn challenge(nonce: &[u8], key: &[u8], message: &[u8]) -> Result<Scalar<Self>>;

    /// Encodes a point known to be nonidentity.
    fn encode_point(point: &RawElement<Self>) -> PointBytes<Self>;

    /// Encodes a prime-order nonce and canonical response scalar.
    fn encode_signature(
        nonce: &PointBytes<Self>,
        response: &ScalarBytes<Self>,
    ) -> Self::SignatureBytes;

    /// Splits a final signature into its point and scalar encodings.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature has the wrong length.
    fn decode_signature(bytes: &[u8]) -> Result<(PointBytes<Self>, ScalarBytes<Self>)>;

    /// Clears a secret scalar.
    fn clear_scalar(scalar: &mut Scalar<Self>);

    /// Converts a small integer to a scalar.
    fn scalar_from_u64(value: u64) -> Scalar<Self>;
}

/// A scalar in profile `P`.
pub type Scalar<P> = <<<P as Profile>::Group as Group>::Field as Field>::Scalar;

/// A raw group element in profile `P`.
pub type RawElement<P> = <<P as Profile>::Group as Group>::Element;

/// A scalar's canonical byte representation in profile `P`.
pub type ScalarBytes<P> = <<<P as Profile>::Group as Group>::Field as Field>::Serialization;

/// A point's canonical byte representation in profile `P`.
pub type PointBytes<P> = <<P as Profile>::Group as Group>::Serialization;

/// KSNF scalar-valued oracle families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashDomain {
    /// Redistribution commitments.
    Deal,
    /// Private member records.
    Member,
    /// Nonce-share commitments.
    Nonce,
    /// FROST binding factors.
    Bind,
}

#[cfg(feature = "ed25519")]
impl HashDomain {
    const fn tag(self) -> u8 {
        match self {
            Self::Deal => 1,
            Self::Member => 2,
            Self::Nonce => 3,
            Self::Bind => 4,
        }
    }
}

/// The secp256k1 plain-Schnorr profile.
#[cfg(feature = "secp256k1")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secp256k1;

#[cfg(feature = "secp256k1")]
impl private::Sealed for Secp256k1 {}

#[cfg(feature = "secp256k1")]
impl Profile for Secp256k1 {
    type Group = frost_secp256k1::Secp256K1Group;
    type SignatureBytes = [u8; 65];

    const WIRE_ID: u8 = 1;
    const PROTOCOL_ID: &'static [u8] = b"coupery-ksnf/v1";
    const MATERIAL_MAGIC: &'static [u8; 8] = b"KSNFMAT1";
    const JOURNAL_MAGIC: &'static [u8; 8] = b"KSNFJNL1";

    fn hash_to_scalar(domain: HashDomain, message: &[u8]) -> Result<Scalar<Self>> {
        use k256::Scalar;
        use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, hash_to_field};
        use sha2::Sha256;

        let dst = match domain {
            HashDomain::Deal => b"KSNF/v1/deal".as_slice(),
            HashDomain::Member => b"KSNF/v1/member".as_slice(),
            HashDomain::Nonce => b"KSNF/v1/nonce".as_slice(),
            HashDomain::Bind => b"KSNF/v1/bind".as_slice(),
        };
        let mut output = [Scalar::ZERO];
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[message], &[dst], &mut output)
            .map_err(|_| Error::HashToField)?;
        Ok(output[0])
    }

    fn challenge(nonce: &[u8], key: &[u8], message: &[u8]) -> Result<Scalar<Self>> {
        use k256::Scalar;
        use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, hash_to_field};
        use sha2::Sha256;

        let message_len = u32::try_from(message.len()).map_err(|_| Error::LengthOverflow)?;
        let mut preimage = Vec::with_capacity(1 + nonce.len() + key.len() + 4 + message.len());
        preimage.push(Self::WIRE_ID);
        preimage.extend_from_slice(nonce);
        preimage.extend_from_slice(key);
        preimage.extend_from_slice(&message_len.to_be_bytes());
        preimage.extend_from_slice(message);
        let mut output = [Scalar::ZERO];
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(
            &[&preimage],
            &[b"KSNF/v1/challenge"],
            &mut output,
        )
        .map_err(|_| Error::HashToField)?;
        Ok(output[0])
    }

    fn encode_point(point: &RawElement<Self>) -> PointBytes<Self> {
        use k256::elliptic_curve::sec1::ToEncodedPoint as _;

        let encoded = point.to_affine().to_encoded_point(true);
        let mut bytes = [0_u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    fn encode_signature(
        nonce: &PointBytes<Self>,
        response: &ScalarBytes<Self>,
    ) -> Self::SignatureBytes {
        let mut bytes = [0_u8; 65];
        bytes[..33].copy_from_slice(nonce.as_ref());
        bytes[33..].copy_from_slice(response.as_ref());
        bytes
    }

    fn decode_signature(bytes: &[u8]) -> Result<(PointBytes<Self>, ScalarBytes<Self>)> {
        let bytes = <&[u8; 65]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        let mut nonce = [0_u8; 33];
        nonce.copy_from_slice(&bytes[..33]);
        let mut response = [0_u8; 32];
        response.copy_from_slice(&bytes[33..]);
        Ok((nonce, response))
    }

    fn clear_scalar(scalar: &mut Scalar<Self>) {
        use zeroize::Zeroize as _;
        scalar.zeroize();
    }

    fn scalar_from_u64(value: u64) -> Scalar<Self> {
        k256::Scalar::from(value)
    }
}

/// The RFC 9591 Ed25519 profile.
#[cfg(feature = "ed25519")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519;

#[cfg(feature = "secp256k1")]
#[doc(hidden)]
pub type DefaultProfile = Secp256k1;

#[cfg(all(not(feature = "secp256k1"), feature = "ed25519"))]
#[doc(hidden)]
pub type DefaultProfile = Ed25519;

#[cfg(feature = "ed25519")]
impl private::Sealed for Ed25519 {}

#[cfg(feature = "ed25519")]
impl Profile for Ed25519 {
    type Group = frost_ed25519::Ed25519Group;
    type SignatureBytes = [u8; 64];

    const WIRE_ID: u8 = 2;
    const PROTOCOL_ID: &'static [u8] = b"coupery-ksnf/ed25519/v1";
    const MATERIAL_MAGIC: &'static [u8; 8] = b"KSNFE1M1";
    const JOURNAL_MAGIC: &'static [u8; 8] = b"KSNFE1J1";

    fn hash_to_scalar(domain: HashDomain, message: &[u8]) -> Result<Scalar<Self>> {
        use frost_core::Ciphersuite as _;

        let message_len = u64::try_from(message.len()).map_err(|_| Error::LengthOverflow)?;
        let mut omega = [0xff_u8; 32];
        omega[0] = 0xed;
        omega[31] = 0x7f;
        let mut preimage = Vec::with_capacity(41 + message.len());
        preimage.extend_from_slice(&omega);
        preimage.push(domain.tag());
        preimage.extend_from_slice(&message_len.to_be_bytes());
        preimage.extend_from_slice(message);
        Ok(frost_ed25519::Ed25519Sha512::H2(&preimage))
    }

    fn challenge(nonce: &[u8], key: &[u8], message: &[u8]) -> Result<Scalar<Self>> {
        use frost_core::Ciphersuite as _;

        let mut preimage = Vec::with_capacity(nonce.len() + key.len() + message.len());
        preimage.extend_from_slice(nonce);
        preimage.extend_from_slice(key);
        preimage.extend_from_slice(message);
        Ok(frost_ed25519::Ed25519Sha512::H2(&preimage))
    }

    fn encode_point(point: &RawElement<Self>) -> PointBytes<Self> {
        point.compress().to_bytes()
    }

    fn encode_signature(
        nonce: &PointBytes<Self>,
        response: &ScalarBytes<Self>,
    ) -> Self::SignatureBytes {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(nonce.as_ref());
        bytes[32..].copy_from_slice(response.as_ref());
        bytes
    }

    fn decode_signature(bytes: &[u8]) -> Result<(PointBytes<Self>, ScalarBytes<Self>)> {
        let bytes = <&[u8; 64]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(&bytes[..32]);
        let mut response = [0_u8; 32];
        response.copy_from_slice(&bytes[32..]);
        Ok((nonce, response))
    }

    fn clear_scalar(scalar: &mut Scalar<Self>) {
        use zeroize::Zeroize as _;
        scalar.zeroize();
    }

    fn scalar_from_u64(value: u64) -> Scalar<Self> {
        value.into()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_domains_cannot_begin_with_a_point() {
        use frost_core::Group as _;

        let mut omega = [0xff_u8; 32];
        omega[0] = 0xed;
        omega[31] = 0x7f;
        assert!(frost_ed25519::Ed25519Group::deserialize(&omega).is_err());
    }
}
