use k256::U256;
use k256::elliptic_curve::PrimeField as _;
use k256::elliptic_curve::ops::Reduce;
use sha2::{Digest as _, Sha256};

use crate::algebra::{Element, Point, Scalar};
use crate::keys::VaultKey;
use crate::{Error, Result};

const TAP_TWEAK_TAG: &[u8] = b"TapTweak";
const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
const EVEN_TAG: u8 = 0x02;
const ODD_TAG: u8 = 0x03;

/// An x-only secp256k1 public key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct XOnlyKey([u8; 32]);

impl XOnlyKey {
    /// Parses an x-only key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPoint`] when the coordinate has no even-Y lift.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Self::try_from(bytes)
    }

    /// Returns the 32-byte key.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(super) fn point(self) -> Result<Point> {
        lift_even(self.0)
    }
}

impl TryFrom<[u8; 32]> for XOnlyKey {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self> {
        lift_even(bytes)?;
        Ok(Self(bytes))
    }
}

impl From<XOnlyKey> for [u8; 32] {
    fn from(key: XOnlyKey) -> Self {
        key.to_bytes()
    }
}

/// A 32-byte BIP-341 signature hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sighash(pub(super) [u8; 32]);

impl Sighash {
    /// Wraps a BIP-341 signature hash.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the hash bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Sighash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl From<Sighash> for [u8; 32] {
    fn from(sighash: Sighash) -> Self {
        sighash.to_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Sign {
    Positive,
    Negative,
}

impl Sign {
    pub(super) const fn value(self) -> i8 {
        match self {
            Self::Positive => 1,
            Self::Negative => -1,
        }
    }

    pub(super) fn scalar(self) -> Scalar {
        match self {
            Self::Positive => Scalar::ONE,
            Self::Negative => -Scalar::ONE,
        }
    }
}

/// A Taproot key-path profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key {
    pub(super) vault: [u8; 33],
    pub(super) merkle_root: Option<[u8; 32]>,
    pub(super) internal_sign: Sign,
    pub(super) output_sign: Sign,
    pub(super) tweak: Scalar,
    pub(super) output: XOnlyKey,
}

impl Key {
    /// Derives a Taproot key from the plain vault key and script tree.
    ///
    /// # Errors
    ///
    /// Returns an error when the BIP-341 tweak is out of range or the tweaked
    /// point is the identity.
    pub fn new(vault: VaultKey, merkle_root: Option<[u8; 32]>) -> Result<Self> {
        let (internal_sign, internal) = even_normalize(vault.point())?;
        let tweak = tap_tweak(internal, merkle_root)?;
        let tweaked = Point::try_from(Element::from(internal) + Element::from_scalar(tweak))
            .map_err(|_| Error::IdentityPoint)?;
        let (output_sign, output) = even_normalize(tweaked)?;
        Ok(Self {
            vault: vault.point().to_bytes(),
            merkle_root,
            internal_sign,
            output_sign,
            tweak,
            output: XOnlyKey(x_only(output)),
        })
    }

    /// Returns the x-only internal key.
    #[must_use]
    pub fn internal_key(self) -> XOnlyKey {
        XOnlyKey(x_only_bytes(self.vault))
    }

    /// Returns the x-only output key.
    #[must_use]
    pub const fn output_key(self) -> XOnlyKey {
        self.output
    }

    /// Returns the script-tree root, if present.
    #[must_use]
    pub const fn merkle_root(self) -> Option<[u8; 32]> {
        self.merkle_root
    }

    /// Returns the BIP-341 tweak.
    #[must_use]
    pub const fn tweak(self) -> Scalar {
        self.tweak
    }

    /// Returns the internal-key sign as `+1` or `-1`.
    #[must_use]
    pub const fn internal_sign(self) -> i8 {
        self.internal_sign.value()
    }

    /// Returns the output-key sign as `+1` or `-1`.
    #[must_use]
    pub const fn output_sign(self) -> i8 {
        self.output_sign.value()
    }
}

pub(super) fn bip340_challenge(nonce: Point, output: Point, sighash: Sighash) -> Scalar {
    let hash = tagged_hash(
        CHALLENGE_TAG,
        &[
            x_only(nonce).as_slice(),
            x_only(output).as_slice(),
            sighash.0.as_slice(),
        ],
    );
    <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
}

pub(super) fn even_normalize(point: Point) -> Result<(Sign, Point)> {
    if point.to_bytes()[0] == ODD_TAG {
        let negated = Point::try_from(Element::identity() - Element::from(point))
            .map_err(|_| Error::IdentityPoint)?;
        Ok((Sign::Negative, negated))
    } else {
        Ok((Sign::Positive, point))
    }
}

pub(super) fn x_only(point: Point) -> [u8; 32] {
    x_only_bytes(point.to_bytes())
}

pub(super) fn lift_even(coordinate: [u8; 32]) -> Result<Point> {
    let mut compressed = [0_u8; 33];
    compressed[0] = EVEN_TAG;
    compressed[1..].copy_from_slice(&coordinate);
    Point::from_bytes(&compressed)
}

fn tap_tweak(internal: Point, merkle_root: Option<[u8; 32]>) -> Result<Scalar> {
    let internal_x = x_only(internal);
    let hash = merkle_root.map_or_else(
        || tagged_hash(TAP_TWEAK_TAG, &[internal_x.as_slice()]),
        |root| tagged_hash(TAP_TWEAK_TAG, &[internal_x.as_slice(), root.as_slice()]),
    );
    Option::<Scalar>::from(Scalar::from_repr(hash.into())).ok_or(Error::InvalidTweak)
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn x_only_bytes(bytes: [u8; 33]) -> [u8; 32] {
    let mut coordinate = [0_u8; 32];
    coordinate.copy_from_slice(&bytes[1..]);
    coordinate
}
