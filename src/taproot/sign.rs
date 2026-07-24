use k256::elliptic_curve::PrimeField as _;

use crate::algebra::{Element, Point, Scalar, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::signing::{self, DeviceNonceSet, Nonce, NoncePair};
use crate::support::OuterSupport;
use crate::transcript::MemberTranscript;
use crate::types::{DeviceId, LeafAttempt, Slot};
use crate::{Error, Result};

use super::key::{Sign, bip340_challenge, even_normalize, lift_even, x_only};
use super::{Package, Sighash, XOnlyKey};

const VERSION: u8 = 1;
const DEVICE_RESPONSE: u8 = 1;
const MEMBER_RESPONSE: u8 = 2;

/// Public hashes for one Taproot signing package.
pub struct SigningContext<'a> {
    package: &'a Package,
    bindings: Vec<(Slot, Scalar)>,
    nonce: Point,
    nonce_sign: Sign,
    challenge: Scalar,
}

impl<'a> SigningContext<'a> {
    pub(super) fn new(package: &'a Package) -> Result<Self> {
        let package_bytes = package.to_bytes()?;
        let mut bindings = Vec::with_capacity(package.root.entries().len());
        let mut pairs = Vec::with_capacity(package.root.entries().len());
        for (index, entry) in package.root.entries().iter().enumerate() {
            let slot = entry.record().slot();
            let index = u16::try_from(index).map_err(|_| Error::LengthOverflow)?;
            let mut preimage = Encoder::new();
            preimage.put_u8(VERSION);
            preimage.put_bytes(&package_bytes)?;
            preimage.put_u16(index);
            let binding = signing::binding_factor::<crate::profile::Secp256k1>(&preimage.finish())?;
            bindings.push((slot, binding));
            pairs.push((entry.nonce(), binding));
        }
        let raw_nonce = signing::aggregate_nonce(&pairs)?;
        let (nonce_sign, nonce) = even_normalize(raw_nonce)?;
        let challenge = bip340_challenge(nonce, package.key.output.point()?, package.sighash());
        Ok(Self {
            package,
            bindings,
            nonce,
            nonce_sign,
            challenge,
        })
    }

    /// Returns the package.
    #[must_use]
    pub const fn package(&self) -> &Package {
        self.package
    }

    /// Returns the even-Y aggregate nonce.
    #[must_use]
    pub const fn nonce(&self) -> Point {
        self.nonce
    }

    /// Returns the nonce sign as `+1` or `-1`.
    #[must_use]
    pub const fn nonce_sign(&self) -> i8 {
        self.nonce_sign.value()
    }

    /// Returns the BIP-340 challenge.
    #[must_use]
    pub const fn challenge(&self) -> Scalar {
        self.challenge
    }

    /// Returns one member's binding factor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the slot is absent.
    pub fn binding(&self, slot: Slot) -> Result<Scalar> {
        self.bindings
            .binary_search_by_key(&slot, |(entry_slot, _)| *entry_slot)
            .map(|index| self.bindings[index].1)
            .map_err(|_| Error::ParticipantNotFound)
    }

    pub(super) fn respond_device(
        &self,
        nonce: Nonce,
        transcript: &MemberTranscript,
        nonces: &DeviceNonceSet,
        device: DeviceId,
        share: &SecretScalar,
    ) -> Result<DeviceResponse> {
        validate_member_inputs(self, transcript, nonces)?;
        let support = transcript.body().inner_support();
        let participant = support.participant(device)?;
        let public_share = share.expose(|value| Element::from_scalar(*value));
        if participant.share().element() != public_share {
            return Err(Error::ShareMismatch);
        }
        if nonce.commitments()? != nonces.nonce(device)? {
            return Err(Error::NonceMismatch);
        }

        let coefficient =
            support.coefficient(device)?.scalar() * transcript.body().outer_coefficient().scalar();
        let binding = self.binding(transcript.slot())?;
        let key = self.package.key;
        let folded = self.challenge
            * key.internal_sign.scalar()
            * key.output_sign.scalar()
            * self.nonce_sign.scalar();
        let partial = nonce.respond(binding, folded, coefficient, share);
        let response = self.nonce_sign.scalar() * partial
            + self.challenge * coefficient * key.output_sign.scalar() * key.tweak;
        Ok(DeviceResponse::new(nonces.attempt(device)?, response))
    }

    /// Verifies and aggregates one member's device responses.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or invalid response.
    pub fn aggregate_member(
        &self,
        transcript: &MemberTranscript,
        nonces: &DeviceNonceSet,
        responses: &[DeviceResponse],
    ) -> Result<MemberResponse> {
        validate_member_inputs(self, transcript, nonces)?;
        let support = transcript.body().inner_support();
        if responses.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        let mut sorted = responses.to_vec();
        sorted.sort_unstable_by_key(|response| response.device());
        reject_duplicate_devices(&sorted)?;

        let binding = self.binding(transcript.slot())?;
        let outer = transcript.body().outer_coefficient();
        let mut response = Scalar::ZERO;
        for (partial, participant) in sorted.iter().zip(support.participants()) {
            if partial.device() != participant.device() {
                return Err(Error::SupportMismatch);
            }
            if partial.attempt() != nonces.attempt(partial.device())? {
                return Err(Error::AttemptMismatch);
            }
            let coefficient = support.coefficient(partial.device())?.scalar() * outer.scalar();
            verify_device(
                *partial,
                &nonces.nonce(partial.device())?,
                binding,
                coefficient,
                participant.share().element(),
                self,
            )?;
            response += partial.scalar;
        }
        verify_member(
            response,
            &nonces.aggregate(),
            binding,
            outer.scalar(),
            transcript.body().member().point(),
            self,
        )?;
        Ok(MemberResponse::new(transcript.slot(), response))
    }

    /// Verifies member responses and returns a BIP-340 signature.
    ///
    /// # Errors
    ///
    /// Returns an error for a support mismatch or invalid response.
    pub fn aggregate_signature(
        &self,
        support: &OuterSupport,
        responses: &[MemberResponse],
    ) -> Result<Signature> {
        self.package.root.validate_support(support)?;
        if responses.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        let mut sorted = responses.to_vec();
        sorted.sort_unstable_by_key(|response| response.slot);
        reject_duplicate_slots(&sorted)?;

        let mut response = Scalar::ZERO;
        for ((partial, participant), entry) in sorted
            .iter()
            .zip(support.participants())
            .zip(self.package.root.entries())
        {
            if partial.slot != participant.slot() || entry.record().slot() != participant.slot() {
                return Err(Error::SupportMismatch);
            }
            verify_member(
                partial.scalar,
                &entry.nonce(),
                self.binding(partial.slot)?,
                support.coefficient(participant.person())?.scalar(),
                participant.member().point(),
                self,
            )?;
            response += partial.scalar;
        }
        let signature = Signature::new(x_only(self.nonce), response);
        signature.verify(self.package.key.output_key(), self.package.sighash())?;
        Ok(signature)
    }
}

/// One Taproot device response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceResponse {
    attempt: LeafAttempt,
    scalar: Scalar,
}

impl DeviceResponse {
    /// Creates a response received from the wire.
    #[must_use]
    pub const fn new(attempt: LeafAttempt, scalar: Scalar) -> Self {
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
    pub const fn scalar(self) -> Scalar {
        self.scalar
    }

    /// Encodes the response in 74 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 74] {
        let mut bytes = [0_u8; 74];
        bytes[0] = VERSION;
        bytes[1] = DEVICE_RESPONSE;
        bytes[2..34].copy_from_slice(self.device().as_bytes());
        bytes[34..42].copy_from_slice(&self.attempt.sequence().to_be_bytes());
        bytes[42..].copy_from_slice(&<[u8; 32]>::from(self.scalar.to_bytes()));
        bytes
    }

    /// Decodes a device response.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown profile or invalid scalar.
    pub fn from_bytes(bytes: &[u8; 74]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        expect_response(&mut decoder, DEVICE_RESPONSE)?;
        let device = DeviceId::new(decoder.get_fixed()?);
        let response = Self {
            attempt: LeafAttempt::new(device, decoder.get_u64()?),
            scalar: decoder.get_scalar()?,
        };
        decoder.finish()?;
        Ok(response)
    }
}

impl TryFrom<&[u8]> for DeviceResponse {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes = <&[u8; 74]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        Self::from_bytes(bytes)
    }
}

impl From<DeviceResponse> for [u8; 74] {
    fn from(response: DeviceResponse) -> Self {
        response.to_bytes()
    }
}

/// One Taproot outer-member response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberResponse {
    slot: Slot,
    scalar: Scalar,
}

impl MemberResponse {
    /// Creates a response received from the wire.
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

    /// Encodes the response in 36 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 36] {
        let mut bytes = [0_u8; 36];
        bytes[0] = VERSION;
        bytes[1] = MEMBER_RESPONSE;
        bytes[2..4].copy_from_slice(&self.slot.get().to_be_bytes());
        bytes[4..].copy_from_slice(&<[u8; 32]>::from(self.scalar.to_bytes()));
        bytes
    }

    /// Decodes a member response.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown profile or invalid scalar.
    pub fn from_bytes(bytes: &[u8; 36]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        expect_response(&mut decoder, MEMBER_RESPONSE)?;
        let response = Self {
            slot: Slot::new(decoder.get_u16()?),
            scalar: decoder.get_scalar()?,
        };
        decoder.finish()?;
        Ok(response)
    }
}

impl TryFrom<&[u8]> for MemberResponse {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes = <&[u8; 36]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        Self::from_bytes(bytes)
    }
}

impl From<MemberResponse> for [u8; 36] {
    fn from(response: MemberResponse) -> Self {
        response.to_bytes()
    }
}

/// A 64-byte BIP-340 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    nonce_x: [u8; 32],
    response: Scalar,
}

impl Signature {
    const fn new(nonce_x: [u8; 32], response: Scalar) -> Self {
        Self { nonce_x, response }
    }

    /// Decodes a BIP-340 signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid nonce coordinate or scalar.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let mut nonce_x = [0_u8; 32];
        nonce_x.copy_from_slice(&bytes[..32]);
        lift_even(nonce_x)?;
        let mut response = [0_u8; 32];
        response.copy_from_slice(&bytes[32..]);
        let response = Option::<Scalar>::from(Scalar::from_repr(response.into()))
            .ok_or(Error::InvalidScalar)?;
        Ok(Self { nonce_x, response })
    }

    /// Returns the 64-byte signature.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.nonce_x);
        bytes[32..].copy_from_slice(&<[u8; 32]>::from(self.response.to_bytes()));
        bytes
    }

    /// Returns the x-only nonce.
    #[must_use]
    pub const fn nonce_x(self) -> [u8; 32] {
        self.nonce_x
    }

    /// Returns the response scalar.
    #[must_use]
    pub const fn response(self) -> Scalar {
        self.response
    }

    /// Verifies the signature under an expected output key.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, nonce, or signature equation.
    pub fn verify(self, key: XOnlyKey, sighash: Sighash) -> Result<()> {
        let nonce = lift_even(self.nonce_x)?;
        let output = key.point()?;
        let challenge = bip340_challenge(nonce, output, sighash);
        let left = Element::from_scalar(self.response);
        let right = Element::from(nonce) + Element::from(output) * challenge;
        if left == right {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

fn validate_member_inputs(
    signing: &SigningContext<'_>,
    transcript: &MemberTranscript,
    nonces: &DeviceNonceSet,
) -> Result<()> {
    if transcript.root() != &signing.package.root {
        return Err(Error::InvalidTranscript);
    }
    let support = transcript.body().inner_support();
    nonces.validate_support(support)?;
    if transcript.root().entry(transcript.slot())?.nonce() != nonces.aggregate() {
        return Err(Error::NonceMismatch);
    }
    Ok(())
}

fn verify_device(
    response: DeviceResponse,
    nonce: &NoncePair,
    binding: Scalar,
    coefficient: Scalar,
    share: Element,
    signing: &SigningContext<'_>,
) -> Result<()> {
    let key = signing.package.key;
    let left = Element::from_scalar(response.scalar);
    let signed_share = share * key.internal_sign.scalar() + Element::generator() * key.tweak;
    let right = (*nonce).bind(binding) * signing.nonce_sign.scalar()
        + signed_share * (signing.challenge * coefficient * key.output_sign.scalar());
    if left == right {
        Ok(())
    } else {
        Err(Error::InvalidPartial)
    }
}

fn verify_member(
    response: Scalar,
    nonce: &NoncePair,
    binding: Scalar,
    coefficient: Scalar,
    member: Point,
    signing: &SigningContext<'_>,
) -> Result<()> {
    let key = signing.package.key;
    let left = Element::from_scalar(response);
    let signed_member =
        Element::from(member) * key.internal_sign.scalar() + Element::generator() * key.tweak;
    let right = (*nonce).bind(binding) * signing.nonce_sign.scalar()
        + signed_member * (signing.challenge * coefficient * key.output_sign.scalar());
    if left == right {
        Ok(())
    } else {
        Err(Error::InvalidPartial)
    }
}

fn reject_duplicate_devices(responses: &[DeviceResponse]) -> Result<()> {
    if responses
        .windows(2)
        .any(|pair| pair[0].device() == pair[1].device())
    {
        Err(Error::DuplicateParticipant)
    } else {
        Ok(())
    }
}

fn reject_duplicate_slots(responses: &[MemberResponse]) -> Result<()> {
    if responses
        .windows(2)
        .any(|pair| pair[0].slot == pair[1].slot)
    {
        Err(Error::DuplicateSlot)
    } else {
        Ok(())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes = <&[u8; 64]>::try_from(bytes).map_err(|_| Error::LengthMismatch)?;
        Self::from_bytes(bytes)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(signature: Signature) -> Self {
        signature.to_bytes()
    }
}

fn expect_response(decoder: &mut Decoder<'_>, kind: u8) -> Result<()> {
    if decoder.get_u8()? != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if decoder.get_u8()? != kind {
        return Err(Error::ProtocolMismatch);
    }
    Ok(())
}
