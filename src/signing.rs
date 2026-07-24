//! Plain Schnorr signing equations.

pub mod hazmat;

use core::fmt;

use frost_core::{Field, Group};

use crate::algebra::{Element, Point, ScalarFor, SecretScalar};
use crate::encoding::Decoder;
use crate::hash::{self, Domain};
use crate::keys::{MemberPoint, SharePoint, VaultKey};
#[cfg(feature = "secp256k1")]
use crate::profile::Secp256k1;
use crate::profile::{DefaultProfile, Profile};
use crate::support::{InnerSupport, OuterSupport};
use crate::transcript::{MemberTranscript, SigningContext};
use crate::types::{DeviceId, LeafAttempt, Slot};
use crate::{Error, Result};

type FieldOf<P> = <<P as Profile>::Group as Group>::Field;

/// A public dual-nonce pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoncePair<P: Profile = DefaultProfile> {
    hiding: Point<P>,
    binding: Point<P>,
}

/// One device's public nonce pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceNonce<P: Profile = DefaultProfile> {
    attempt: LeafAttempt,
    nonce: NoncePair<P>,
}

impl<P: Profile> DeviceNonce<P> {
    /// Creates a device nonce.
    #[must_use]
    pub const fn new(attempt: LeafAttempt, nonce: NoncePair<P>) -> Self {
        Self { attempt, nonce }
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.attempt.device()
    }

    /// Returns the leaf attempt.
    #[must_use]
    pub const fn attempt(self) -> LeafAttempt {
        self.attempt
    }

    /// Returns the public nonce pair.
    #[must_use]
    pub const fn nonce(self) -> NoncePair<P> {
        self.nonce
    }
}

/// A fixed, canonical set of device nonces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceNonceSet<P: Profile = DefaultProfile> {
    entries: Vec<DeviceNonce<P>>,
    aggregate: NoncePair<P>,
}

impl<P: Profile> DeviceNonceSet<P> {
    /// Creates a nonce set for an accepted inner support.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate, missing, or identity sum.
    pub fn new(support: &InnerSupport<P>, mut entries: Vec<DeviceNonce<P>>) -> Result<Self> {
        entries.sort_unstable_by_key(|entry| entry.device());
        if entries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        for pair in entries.windows(2) {
            if pair[0].device() == pair[1].device() {
                return Err(Error::DuplicateParticipant);
            }
        }
        for (entry, participant) in entries.iter().zip(support.participants()) {
            if entry.device() != participant.device() {
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
    pub fn nonce(&self, device: DeviceId) -> Result<NoncePair<P>> {
        self.entries
            .binary_search_by_key(&device, |entry| entry.device())
            .map(|index| self.entries[index].nonce)
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns one device's leaf attempt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the device is absent.
    pub fn attempt(&self, device: DeviceId) -> Result<LeafAttempt> {
        self.entries
            .binary_search_by_key(&device, |entry| entry.device())
            .map(|index| self.entries[index].attempt)
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the member nonce pair.
    #[must_use]
    pub const fn aggregate(&self) -> NoncePair<P> {
        self.aggregate
    }

    pub(crate) fn validate_support(&self, support: &InnerSupport<P>) -> Result<()> {
        if self.entries.len() != support.participants().len()
            || self
                .entries
                .iter()
                .zip(support.participants())
                .any(|(entry, participant)| entry.device() != participant.device())
        {
            Err(Error::SupportMismatch)
        } else {
            Ok(())
        }
    }
}

/// One device response.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceResponse<P: Profile = DefaultProfile> {
    attempt: LeafAttempt,
    scalar: ScalarFor<P>,
}

impl<P: Profile> DeviceResponse<P> {
    /// Creates a device response received from the wire.
    #[must_use]
    pub const fn new(attempt: LeafAttempt, scalar: ScalarFor<P>) -> Self {
        Self { attempt, scalar }
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.attempt.device()
    }

    /// Returns the leaf attempt.
    #[must_use]
    pub const fn attempt(self) -> LeafAttempt {
        self.attempt
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn scalar(self) -> ScalarFor<P> {
        self.scalar
    }

    /// Encodes the response in 73 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 73] {
        let mut bytes = [0_u8; 73];
        bytes[0] = P::WIRE_ID;
        bytes[1..33].copy_from_slice(self.device().as_bytes());
        bytes[33..41].copy_from_slice(&self.attempt.sequence().to_be_bytes());
        bytes[41..].copy_from_slice(FieldOf::<P>::serialize(&self.scalar).as_ref());
        bytes
    }

    /// Decodes a device response.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version or invalid scalar.
    pub fn from_bytes(bytes: &[u8; 73]) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        if decoder.get_u8()? != P::WIRE_ID {
            return Err(Error::UnsupportedVersion);
        }
        let device = DeviceId::new(decoder.get_fixed()?);
        let response = Self {
            attempt: LeafAttempt::new(device, decoder.get_u64()?),
            scalar: decoder.get_scalar()?,
        };
        decoder.finish()?;
        Ok(response)
    }
}

impl<P: Profile> TryFrom<&[u8]> for DeviceResponse<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes = <&[u8; 73]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        Self::from_bytes(bytes)
    }
}

impl<P: Profile> From<DeviceResponse<P>> for [u8; 73] {
    fn from(response: DeviceResponse<P>) -> Self {
        response.to_bytes()
    }
}

impl<P: Profile> fmt::Debug for DeviceResponse<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceResponse")
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

/// One outer member response.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemberResponse<P: Profile = DefaultProfile> {
    slot: Slot,
    scalar: ScalarFor<P>,
}

impl<P: Profile> MemberResponse<P> {
    /// Creates a member response received from the wire.
    #[must_use]
    pub const fn new(slot: Slot, scalar: ScalarFor<P>) -> Self {
        Self { slot, scalar }
    }

    /// Returns the outer slot.
    #[must_use]
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn scalar(self) -> ScalarFor<P> {
        self.scalar
    }

    /// Encodes the response in 35 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 35] {
        let mut bytes = [0_u8; 35];
        bytes[0] = P::WIRE_ID;
        bytes[1..3].copy_from_slice(&self.slot.get().to_be_bytes());
        bytes[3..].copy_from_slice(FieldOf::<P>::serialize(&self.scalar).as_ref());
        bytes
    }

    /// Decodes a member response.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version or invalid scalar.
    pub fn from_bytes(bytes: &[u8; 35]) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        if decoder.get_u8()? != P::WIRE_ID {
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

impl<P: Profile> TryFrom<&[u8]> for MemberResponse<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes = <&[u8; 35]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        Self::from_bytes(bytes)
    }
}

impl<P: Profile> From<MemberResponse<P>> for [u8; 35] {
    fn from(response: MemberResponse<P>) -> Self {
        response.to_bytes()
    }
}

impl<P: Profile> fmt::Debug for MemberResponse<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemberResponse")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl<P: Profile> NoncePair<P> {
    /// Creates a public nonce pair.
    #[must_use]
    pub const fn new(hiding: Point<P>, binding: Point<P>) -> Self {
        Self { hiding, binding }
    }

    /// Returns the hiding commitment.
    #[must_use]
    pub const fn hiding(self) -> Point<P> {
        self.hiding
    }

    /// Returns the binding commitment.
    #[must_use]
    pub const fn binding(self) -> Point<P> {
        self.binding
    }

    /// Combines the pair under `binding_factor`.
    #[must_use]
    pub fn bind(self, binding_factor: ScalarFor<P>) -> Element<P> {
        Element::from(self.hiding) + Element::from(self.binding) * binding_factor
    }
}

/// A volatile dual nonce.
pub struct Nonce<P: Profile = DefaultProfile> {
    hiding: ScalarFor<P>,
    binding: ScalarFor<P>,
}

impl<P: Profile> Nonce<P> {
    /// Creates a nonce from two nonzero scalars.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNonce`] when either scalar is zero.
    pub fn new(hiding: ScalarFor<P>, binding: ScalarFor<P>) -> Result<Self> {
        if hiding == FieldOf::<P>::zero() || binding == FieldOf::<P>::zero() {
            Err(Error::ZeroNonce)
        } else {
            Ok(Self { hiding, binding })
        }
    }

    /// Samples two nonzero scalars.
    #[must_use]
    pub fn sample(rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore)) -> Self {
        Self {
            hiding: random_nonzero::<P>(rng),
            binding: random_nonzero::<P>(rng),
        }
    }

    /// Returns the public nonce pair.
    ///
    /// # Errors
    ///
    /// Returns an error if either scalar maps to the identity.
    pub fn commitments(&self) -> Result<NoncePair<P>> {
        Ok(NoncePair::new(
            Point::from_scalar(self.hiding)?,
            Point::from_scalar(self.binding)?,
        ))
    }

    /// Consumes the nonce and returns one response scalar.
    #[must_use]
    pub fn respond(
        self,
        binding_factor: ScalarFor<P>,
        challenge: ScalarFor<P>,
        coefficient: ScalarFor<P>,
        signing_share: &SecretScalar<P>,
    ) -> ScalarFor<P> {
        signing_share.expose(|share| {
            self.hiding + binding_factor * self.binding + challenge * coefficient * *share
        })
    }
}

impl<P: Profile> Drop for Nonce<P> {
    fn drop(&mut self) {
        P::clear_scalar(&mut self.hiding);
        P::clear_scalar(&mut self.binding);
    }
}

/// A plain Schnorr signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Signature<P: Profile = DefaultProfile> {
    nonce: Point<P>,
    response: ScalarFor<P>,
}

impl<P: Profile> Signature<P> {
    /// Creates a signature.
    #[must_use]
    pub const fn new(nonce: Point<P>, response: ScalarFor<P>) -> Self {
        Self { nonce, response }
    }

    /// Returns the aggregate nonce.
    #[must_use]
    pub const fn nonce(self) -> Point<P> {
        self.nonce
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn response(self) -> ScalarFor<P> {
        self.response
    }

    /// Encodes `R || z` in the profile's final signature form.
    #[must_use]
    pub fn to_bytes(self) -> P::SignatureBytes {
        P::encode_signature(
            &self.nonce.to_bytes(),
            &FieldOf::<P>::serialize(&self.response),
        )
    }

    /// Decodes `R || z`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid point or scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (nonce, response) = P::decode_signature(bytes)?;
        let nonce = Point::<P>::from_bytes(nonce.as_ref())?;
        let response = FieldOf::<P>::deserialize(&response).map_err(|_| Error::InvalidScalar)?;
        Ok(Self { nonce, response })
    }

    /// Verifies the signature under `key` and `message`.
    ///
    /// # Errors
    ///
    /// Returns an error when hashing fails or the equation does not hold.
    pub fn verify(self, key: VaultKey<P>, message: &[u8]) -> Result<()> {
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

impl<P: Profile> TryFrom<&[u8]> for Signature<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

#[cfg(feature = "secp256k1")]
impl From<Signature<Secp256k1>> for [u8; 65] {
    fn from(signature: Signature<Secp256k1>) -> Self {
        signature.to_bytes()
    }
}

#[cfg(feature = "ed25519")]
impl From<Signature<crate::profile::Ed25519>> for [u8; 64] {
    fn from(signature: Signature<crate::profile::Ed25519>) -> Self {
        signature.to_bytes()
    }
}

impl<P: Profile> fmt::Debug for Signature<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Signature")
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

/// Derives a FROST binding factor from canonical bytes.
///
/// # Errors
///
/// Returns an error when hash-to-field fails.
pub fn binding_factor<P: Profile>(preimage: &[u8]) -> Result<ScalarFor<P>> {
    hash::to_scalar_for::<P>(Domain::Bind, preimage)
}

/// Derives a plain Schnorr challenge.
///
/// # Errors
///
/// Returns an error when `message` is too long or hashing fails.
pub fn challenge<P: Profile>(
    nonce: Point<P>,
    key: VaultKey<P>,
    message: &[u8],
) -> Result<ScalarFor<P>> {
    P::challenge(nonce.to_bytes().as_ref(), key.to_bytes().as_ref(), message)
}

/// Aggregates bound nonce pairs.
///
/// # Errors
///
/// Returns an error for an empty input or identity sum.
pub fn aggregate_nonce<P: Profile>(pairs: &[(NoncePair<P>, ScalarFor<P>)]) -> Result<Point<P>> {
    if pairs.is_empty() {
        return Err(Error::EmptyInput);
    }
    let aggregate = pairs
        .iter()
        .fold(Element::identity(), |sum, (pair, binding_factor)| {
            sum + pair.bind(*binding_factor)
        });
    Point::try_from(aggregate).map_err(|_| Error::IdentityNonce)
}

/// Checks one device response.
///
/// # Errors
///
/// Returns [`Error::InvalidPartial`] when the equation does not hold.
pub fn verify_device<P: Profile>(
    response: ScalarFor<P>,
    nonce: NoncePair<P>,
    binding_factor: ScalarFor<P>,
    challenge: ScalarFor<P>,
    coefficient: ScalarFor<P>,
    share: SharePoint<P>,
) -> Result<()> {
    let left = Element::from_scalar(response);
    let right = nonce.bind(binding_factor) + share.element() * (challenge * coefficient);
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
pub fn verify_member<P: Profile>(
    response: ScalarFor<P>,
    nonce: NoncePair<P>,
    binding_factor: ScalarFor<P>,
    challenge: ScalarFor<P>,
    outer_coefficient: ScalarFor<P>,
    member: MemberPoint<P>,
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
pub(crate) fn respond_device<P: Profile>(
    nonce: Nonce<P>,
    transcript: &MemberTranscript<P>,
    signing: &SigningContext<'_, P>,
    nonces: &DeviceNonceSet<P>,
    device: DeviceId,
    share: &SecretScalar<P>,
) -> Result<DeviceResponse<P>> {
    validate_member_inputs(transcript, signing, nonces)?;
    let participant = transcript.body().inner_support().participant(device)?;
    let public_share = share.expose(|scalar| Element::from_scalar(*scalar));
    if participant.share().element() != public_share {
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
    Ok(DeviceResponse::new(nonces.attempt(device)?, response))
}

/// Verifies and aggregates one member's device responses.
///
/// # Errors
///
/// Returns an error for a missing, duplicate, or invalid response.
pub fn aggregate_member<P: Profile>(
    transcript: &MemberTranscript<P>,
    signing: &SigningContext<'_, P>,
    nonces: &DeviceNonceSet<P>,
    responses: &[DeviceResponse<P>],
) -> Result<MemberResponse<P>> {
    validate_member_inputs(transcript, signing, nonces)?;
    let support = transcript.body().inner_support();
    if responses.len() != support.participants().len() {
        return Err(Error::SupportMismatch);
    }
    let mut sorted = responses.to_vec();
    sorted.sort_unstable_by_key(|response| response.device());
    for pair in sorted.windows(2) {
        if pair[0].device() == pair[1].device() {
            return Err(Error::DuplicateParticipant);
        }
    }

    let binding = signing.binding(transcript.slot())?;
    let outer = transcript.body().outer_coefficient();
    let mut response = FieldOf::<P>::zero();
    for (partial, participant) in sorted.iter().zip(support.participants()) {
        if partial.device() != participant.device() {
            return Err(Error::SupportMismatch);
        }
        if partial.attempt() != nonces.attempt(partial.device())? {
            return Err(Error::AttemptMismatch);
        }
        let coefficient = support.coefficient(partial.device())?.scalar() * outer.scalar();
        verify_device(
            partial.scalar,
            nonces.nonce(partial.device())?,
            binding,
            signing.challenge(),
            coefficient,
            participant.share(),
        )?;
        response = response + partial.scalar;
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
pub fn aggregate_signature<P: Profile>(
    signing: &SigningContext<'_, P>,
    support: &OuterSupport<P>,
    responses: &[MemberResponse<P>],
) -> Result<Signature<P>> {
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

    let mut response = FieldOf::<P>::zero();
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
        response = response + partial.scalar;
    }
    let signature = Signature::new(signing.nonce(), response);
    signature.verify(signing.root().key(), signing.root().message())?;
    Ok(signature)
}

fn validate_member_inputs<P: Profile>(
    transcript: &MemberTranscript<P>,
    signing: &SigningContext<'_, P>,
    nonces: &DeviceNonceSet<P>,
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

fn sum_nonce_pairs<P: Profile>(pairs: impl Iterator<Item = NoncePair<P>>) -> Result<NoncePair<P>> {
    let (hiding, binding) = pairs.fold(
        (Element::identity(), Element::identity()),
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

fn random_nonzero<P: Profile>(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> ScalarFor<P> {
    loop {
        let scalar = FieldOf::<P>::random(&mut *rng);
        if scalar != FieldOf::<P>::zero() {
            return scalar;
        }
    }
}
