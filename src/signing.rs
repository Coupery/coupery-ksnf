//! Plain Schnorr signing equations.

use k256::elliptic_curve::Field as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algebra::{Element, Point, Scalar, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::hash::{self, Domain};
use crate::keys::{MemberPoint, SharePoint, VaultKey};
use crate::support::{InnerSupport, OuterSupport};
use crate::transcript::{MemberTranscript, SigningContext};
use crate::types::{DeviceId, Slot};
use crate::{Error, Result};

/// A public dual-nonce pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoncePair {
    hiding: Point,
    binding: Point,
}

/// One device's public nonce pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceNonce {
    device: DeviceId,
    nonce: NoncePair,
}

impl DeviceNonce {
    /// Creates a device nonce.
    #[must_use]
    pub const fn new(device: DeviceId, nonce: NoncePair) -> Self {
        Self { device, nonce }
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the public nonce pair.
    #[must_use]
    pub const fn nonce(self) -> NoncePair {
        self.nonce
    }
}

/// A fixed, canonical set of device nonces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceNonceSet {
    entries: Vec<DeviceNonce>,
    aggregate: NoncePair,
}

impl DeviceNonceSet {
    /// Creates a nonce set for an accepted inner support.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate, missing, or identity sum.
    pub fn new(support: &InnerSupport, mut entries: Vec<DeviceNonce>) -> Result<Self> {
        entries.sort_unstable_by_key(|entry| entry.device);
        if entries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        for pair in entries.windows(2) {
            if pair[0].device == pair[1].device {
                return Err(Error::DuplicateParticipant);
            }
        }
        for (entry, participant) in entries.iter().zip(support.participants()) {
            if entry.device != participant.device() {
                return Err(Error::SupportMismatch);
            }
        }
        let aggregate = sum_nonce_pairs(entries.iter().map(|entry| entry.nonce))?;
        Ok(Self { entries, aggregate })
    }

    /// Returns one device's nonce pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the device is absent.
    pub fn nonce(&self, device: DeviceId) -> Result<NoncePair> {
        self.entries
            .binary_search_by_key(&device, |entry| entry.device)
            .map(|index| self.entries[index].nonce)
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the member nonce pair.
    #[must_use]
    pub const fn aggregate(&self) -> NoncePair {
        self.aggregate
    }

    fn validate_support(&self, support: &InnerSupport) -> Result<()> {
        if self.entries.len() != support.participants().len()
            || self
                .entries
                .iter()
                .zip(support.participants())
                .any(|(entry, participant)| entry.device != participant.device())
        {
            Err(Error::SupportMismatch)
        } else {
            Ok(())
        }
    }
}

/// One device response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceResponse {
    device: DeviceId,
    scalar: Scalar,
}

impl DeviceResponse {
    /// Creates a device response received from the wire.
    #[must_use]
    pub const fn new(device: DeviceId, scalar: Scalar) -> Self {
        Self { device, scalar }
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn scalar(self) -> Scalar {
        self.scalar
    }

    /// Encodes the response in 65 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 65] {
        let mut bytes = [0_u8; 65];
        bytes[0] = 1;
        bytes[1..33].copy_from_slice(self.device.as_bytes());
        bytes[33..].copy_from_slice(&<[u8; 32]>::from(self.scalar.to_bytes()));
        bytes
    }

    /// Decodes a device response.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version or invalid scalar.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.get_u8()? != 1 {
            return Err(Error::UnsupportedVersion);
        }
        let response = Self {
            device: DeviceId::new(decoder.get_fixed()?),
            scalar: decoder.get_scalar()?,
        };
        decoder.finish()?;
        Ok(response)
    }
}

/// One outer member response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberResponse {
    slot: Slot,
    scalar: Scalar,
}

impl MemberResponse {
    /// Creates a member response received from the wire.
    #[must_use]
    pub const fn new(slot: Slot, scalar: Scalar) -> Self {
        Self { slot, scalar }
    }

    /// Returns the outer slot.
    #[must_use]
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn scalar(self) -> Scalar {
        self.scalar
    }

    /// Encodes the response in 35 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 35] {
        let mut bytes = [0_u8; 35];
        bytes[0] = 1;
        bytes[1..3].copy_from_slice(&self.slot.get().to_be_bytes());
        bytes[3..].copy_from_slice(&<[u8; 32]>::from(self.scalar.to_bytes()));
        bytes
    }

    /// Decodes a member response.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version or invalid scalar.
    pub fn from_bytes(bytes: &[u8; 35]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.get_u8()? != 1 {
            return Err(Error::UnsupportedVersion);
        }
        let response = Self {
            slot: Slot::new(decoder.get_u16()?),
            scalar: decoder.get_scalar()?,
        };
        decoder.finish()?;
        Ok(response)
    }
}

impl NoncePair {
    /// Creates a public nonce pair.
    #[must_use]
    pub const fn new(hiding: Point, binding: Point) -> Self {
        Self { hiding, binding }
    }

    /// Returns the hiding commitment.
    #[must_use]
    pub const fn hiding(self) -> Point {
        self.hiding
    }

    /// Returns the binding commitment.
    #[must_use]
    pub const fn binding(self) -> Point {
        self.binding
    }

    /// Combines the pair under `binding_factor`.
    #[must_use]
    pub fn bind(self, binding_factor: Scalar) -> Element {
        Element::from(self.hiding) + Element::from(self.binding) * binding_factor
    }
}

/// A volatile dual nonce.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Nonce {
    hiding: Scalar,
    binding: Scalar,
}

impl Nonce {
    /// Creates a nonce from two nonzero scalars.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNonce`] when either scalar is zero.
    pub fn new(hiding: Scalar, binding: Scalar) -> Result<Self> {
        if hiding == Scalar::ZERO || binding == Scalar::ZERO {
            Err(Error::ZeroNonce)
        } else {
            Ok(Self { hiding, binding })
        }
    }

    /// Samples two nonzero scalars.
    #[must_use]
    pub fn sample(rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore)) -> Self {
        Self {
            hiding: random_nonzero(rng),
            binding: random_nonzero(rng),
        }
    }

    /// Returns the public nonce pair.
    ///
    /// # Errors
    ///
    /// Returns an error if either scalar maps to the identity.
    pub fn commitments(&self) -> Result<NoncePair> {
        Ok(NoncePair::new(
            Point::from_scalar(self.hiding)?,
            Point::from_scalar(self.binding)?,
        ))
    }

    /// Consumes the nonce and returns one response scalar.
    #[must_use]
    pub fn respond(
        self,
        binding_factor: Scalar,
        challenge: Scalar,
        coefficient: Scalar,
        signing_share: &SecretScalar,
    ) -> Scalar {
        signing_share.expose(|share| {
            self.hiding + binding_factor * self.binding + challenge * coefficient * share
        })
    }
}

/// A plain Schnorr signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    nonce: Point,
    response: Scalar,
}

impl Signature {
    /// Creates a signature.
    #[must_use]
    pub const fn new(nonce: Point, response: Scalar) -> Self {
        Self { nonce, response }
    }

    /// Returns the aggregate nonce.
    #[must_use]
    pub const fn nonce(self) -> Point {
        self.nonce
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn response(self) -> Scalar {
        self.response
    }

    /// Encodes `R || z` in 65 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 65] {
        let mut bytes = [0_u8; 65];
        bytes[..33].copy_from_slice(&self.nonce.to_bytes());
        bytes[33..].copy_from_slice(&<[u8; 32]>::from(self.response.to_bytes()));
        bytes
    }

    /// Decodes `R || z`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid point or scalar.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let nonce = decoder.get_point()?;
        let response = decoder.get_scalar()?;
        decoder.finish()?;
        Ok(Self { nonce, response })
    }

    /// Verifies the signature under `key` and `message`.
    ///
    /// # Errors
    ///
    /// Returns an error when hashing fails or the equation does not hold.
    pub fn verify(self, key: VaultKey, message: &[u8]) -> Result<()> {
        let challenge = challenge(self.nonce, key, message)?;
        let left = Element::from_scalar(self.response);
        let right = Element::from(self.nonce) + Element::from(key.point()) * challenge;
        if left == right {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// Derives a FROST binding factor from canonical bytes.
///
/// # Errors
///
/// Returns an error when hash-to-field fails.
pub fn binding_factor(preimage: &[u8]) -> Result<Scalar> {
    hash::to_scalar(Domain::Bind, preimage)
}

/// Derives a plain Schnorr challenge.
///
/// # Errors
///
/// Returns an error when `message` is too long or hashing fails.
pub fn challenge(nonce: Point, key: VaultKey, message: &[u8]) -> Result<Scalar> {
    let mut encoder = Encoder::new();
    encoder.put_u8(1);
    encoder.put_point(nonce);
    encoder.put_point(key.point());
    encoder.put_bytes(message)?;
    hash::to_scalar(Domain::Challenge, &encoder.finish())
}

/// Aggregates bound nonce pairs.
///
/// # Errors
///
/// Returns an error for an empty input or identity sum.
pub fn aggregate_nonce(pairs: &[(NoncePair, Scalar)]) -> Result<Point> {
    if pairs.is_empty() {
        return Err(Error::EmptyInput);
    }
    let aggregate = pairs
        .iter()
        .fold(Element::IDENTITY, |sum, (pair, binding_factor)| {
            sum + pair.bind(*binding_factor)
        });
    Point::try_from(aggregate).map_err(|_| Error::IdentityNonce)
}

/// Checks one device response.
///
/// # Errors
///
/// Returns [`Error::InvalidPartial`] when the equation does not hold.
pub fn verify_device(
    response: Scalar,
    nonce: NoncePair,
    binding_factor: Scalar,
    challenge: Scalar,
    coefficient: Scalar,
    share: SharePoint,
) -> Result<()> {
    let left = Element::from_scalar(response);
    let right =
        nonce.bind(binding_factor) + Element::from(share.point()) * (challenge * coefficient);
    if left == right {
        Ok(())
    } else {
        Err(Error::InvalidPartial)
    }
}

/// Checks one outer member response.
///
/// # Errors
///
/// Returns [`Error::InvalidPartial`] when the equation does not hold.
pub fn verify_member(
    response: Scalar,
    nonce: NoncePair,
    binding_factor: Scalar,
    challenge: Scalar,
    outer_coefficient: Scalar,
    member: MemberPoint,
) -> Result<()> {
    let left = Element::from_scalar(response);
    let right = nonce.bind(binding_factor)
        + Element::from(member.point()) * (challenge * outer_coefficient);
    if left == right {
        Ok(())
    } else {
        Err(Error::InvalidPartial)
    }
}

/// Produces one device response from a verified member transcript.
///
/// # Errors
///
/// Returns an error when the transcript, nonce set, share, or nonce differs
/// from its public value.
pub fn respond_device(
    nonce: Nonce,
    transcript: &MemberTranscript,
    signing: &SigningContext<'_>,
    nonces: &DeviceNonceSet,
    device: DeviceId,
    share: &SecretScalar,
) -> Result<DeviceResponse> {
    validate_member_inputs(transcript, signing, nonces)?;
    let participant = transcript.body().inner_support().participant(device)?;
    let public_share = share.expose(|scalar| Point::from_scalar(*scalar))?;
    if participant.share().point() != public_share {
        return Err(Error::ShareMismatch);
    }
    if nonce.commitments()? != nonces.nonce(device)? {
        return Err(Error::NonceMismatch);
    }

    let inner = transcript.body().inner_support().coefficient(device)?;
    let outer = transcript.body().outer_coefficient();
    let binding = signing.binding(transcript.slot())?;
    let response = nonce.respond(
        binding,
        signing.challenge(),
        inner.scalar() * outer.scalar(),
        share,
    );
    Ok(DeviceResponse::new(device, response))
}

/// Verifies and aggregates one member's device responses.
///
/// # Errors
///
/// Returns an error for a missing, duplicate, or invalid response.
pub fn aggregate_member(
    transcript: &MemberTranscript,
    signing: &SigningContext<'_>,
    nonces: &DeviceNonceSet,
    responses: &[DeviceResponse],
) -> Result<MemberResponse> {
    validate_member_inputs(transcript, signing, nonces)?;
    let support = transcript.body().inner_support();
    if responses.len() != support.participants().len() {
        return Err(Error::SupportMismatch);
    }
    let mut sorted = responses.to_vec();
    sorted.sort_unstable_by_key(|response| response.device);
    for pair in sorted.windows(2) {
        if pair[0].device == pair[1].device {
            return Err(Error::DuplicateParticipant);
        }
    }

    let binding = signing.binding(transcript.slot())?;
    let outer = transcript.body().outer_coefficient();
    let mut response = Scalar::ZERO;
    for (partial, participant) in sorted.iter().zip(support.participants()) {
        if partial.device != participant.device() {
            return Err(Error::SupportMismatch);
        }
        let coefficient = support.coefficient(partial.device)?.scalar() * outer.scalar();
        verify_device(
            partial.scalar,
            nonces.nonce(partial.device)?,
            binding,
            signing.challenge(),
            coefficient,
            participant.share(),
        )?;
        response += partial.scalar;
    }
    verify_member(
        response,
        nonces.aggregate,
        binding,
        signing.challenge(),
        outer.scalar(),
        transcript.body().member(),
    )?;
    Ok(MemberResponse::new(transcript.slot(), response))
}

/// Verifies outer responses and returns a plain Schnorr signature.
///
/// # Errors
///
/// Returns an error for a support mismatch or invalid response.
pub fn aggregate_signature(
    signing: &SigningContext<'_>,
    support: &OuterSupport,
    responses: &[MemberResponse],
) -> Result<Signature> {
    signing.root().validate_support(support)?;
    if responses.len() != support.participants().len() {
        return Err(Error::SupportMismatch);
    }
    let mut sorted = responses.to_vec();
    sorted.sort_unstable_by_key(|response| response.slot);
    for pair in sorted.windows(2) {
        if pair[0].slot == pair[1].slot {
            return Err(Error::DuplicateSlot);
        }
    }

    let mut response = Scalar::ZERO;
    for ((partial, participant), entry) in sorted
        .iter()
        .zip(support.participants())
        .zip(signing.root().entries())
    {
        if partial.slot != participant.slot() || entry.record().slot() != participant.slot() {
            return Err(Error::SupportMismatch);
        }
        let coefficient = support.coefficient(participant.person())?;
        verify_member(
            partial.scalar,
            entry.nonce(),
            signing.binding(partial.slot)?,
            signing.challenge(),
            coefficient.scalar(),
            participant.member(),
        )?;
        response += partial.scalar;
    }
    let signature = Signature::new(signing.nonce(), response);
    signature.verify(signing.root().key(), signing.root().message())?;
    Ok(signature)
}

fn validate_member_inputs(
    transcript: &MemberTranscript,
    signing: &SigningContext<'_>,
    nonces: &DeviceNonceSet,
) -> Result<()> {
    if transcript.root() != signing.root() {
        return Err(Error::InvalidTranscript);
    }
    let support = transcript.body().inner_support();
    nonces.validate_support(support)?;
    if transcript.root().entry(transcript.slot())?.nonce() != nonces.aggregate {
        return Err(Error::NonceMismatch);
    }
    Ok(())
}

fn sum_nonce_pairs(pairs: impl Iterator<Item = NoncePair>) -> Result<NoncePair> {
    let (hiding, binding) = pairs.fold(
        (Element::IDENTITY, Element::IDENTITY),
        |(hiding, binding), pair| {
            (
                hiding + Element::from(pair.hiding),
                binding + Element::from(pair.binding),
            )
        },
    );
    Ok(NoncePair::new(
        Point::try_from(hiding).map_err(|_| Error::IdentityNonce)?,
        Point::try_from(binding).map_err(|_| Error::IdentityNonce)?,
    ))
}

fn random_nonzero(rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore)) -> Scalar {
    loop {
        let scalar = Scalar::random(&mut *rng);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}
