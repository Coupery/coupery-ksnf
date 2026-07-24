//! Canonical signing transcripts.

use core::fmt;

use frost_core::{Field, Group};
use zeroize::Zeroizing;

use crate::algebra::{Point, ScalarFor, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::hash::{self, Domain};
use crate::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
#[cfg(feature = "secp256k1")]
use crate::profile::Secp256k1;
use crate::profile::{DefaultProfile, Profile};
use crate::shamir::Node;
use crate::signing::{self, NoncePair};
use crate::support::{DeviceParticipant, InnerSupport, OuterCoefficient, OuterSupport};
use crate::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, SessionId, Slot,
    VaultId,
};
use crate::{Error, Result};

type FieldOf<P> = <<P as Profile>::Group as Group>::Field;

/// The fixed protocol identifier.
#[cfg(feature = "secp256k1")]
pub const PROTOCOL_ID: &[u8] = Secp256k1::PROTOCOL_ID;

/// A private member commitment body.
#[derive(Clone, Eq, PartialEq)]
pub struct MemberBody<P: Profile = DefaultProfile> {
    identity: IdentityKey<P>,
    member: MemberPoint<P>,
    epoch: KeyEpoch,
    inner: InnerSupport<P>,
    outer: OuterCoefficient<P>,
}

impl<P: Profile> fmt::Debug for MemberBody<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemberBody([REDACTED])")
    }
}

impl<P: Profile> MemberBody<P> {
    /// Creates a body from accepted supports.
    ///
    /// # Errors
    ///
    /// Returns an error when its person or member values disagree.
    pub fn new(
        identity: IdentityKey<P>,
        member: MemberPoint<P>,
        epoch: KeyEpoch,
        inner: InnerSupport<P>,
        outer: OuterCoefficient<P>,
    ) -> Result<Self> {
        if epoch.anchor().person() != outer.person() {
            return Err(Error::ParticipantMismatch);
        }
        if member != outer.member() {
            return Err(Error::SupportMismatch);
        }
        Ok(Self {
            identity,
            member,
            epoch,
            inner,
            outer,
        })
    }

    /// Decodes a body and checks its outer coefficients.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or a support mismatch.
    pub fn from_bytes(bytes: &[u8], outer_support: &OuterSupport<P>) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let identity = IdentityKey::new(decoder.get_point()?);
        let member = MemberPoint::new(decoder.get_point()?);
        let epoch = decode_key_epoch(&mut decoder)?;
        let count = usize::from(decoder.get_u16()?);
        if count == 0 {
            return Err(Error::EmptyInput);
        }

        let mut participants = Vec::with_capacity(count);
        let mut encoded_coefficients = Vec::with_capacity(count);
        for _ in 0..count {
            participants.push(DeviceParticipant::new(
                DeviceId::new(decoder.get_fixed()?),
                Node::new(decoder.get_scalar()?)?,
                SharePoint::new(decoder.get_element()?),
            ));
            encoded_coefficients.push(decoder.get_scalar()?);
        }

        let person = PersonId::new(decoder.get_fixed()?);
        let slot = Slot::new(decoder.get_u16()?);
        let encoded_outer = decoder.get_scalar()?;
        decoder.finish()?;

        let encoded_order = participants.clone();
        let inner = InnerSupport::new(participants)?;
        if inner.participants() != encoded_order {
            return Err(Error::InvalidTranscript);
        }
        for (participant, encoded) in inner.participants().iter().zip(encoded_coefficients) {
            if inner.coefficient(participant.device())?.scalar() != encoded {
                return Err(Error::CoefficientMismatch);
            }
        }

        let outer = outer_support.coefficient(person)?;
        if outer.slot() != slot || outer.scalar() != encoded_outer {
            return Err(Error::CoefficientMismatch);
        }
        Self::new(identity, member, epoch, inner, outer)
    }

    /// Returns the canonical body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for more than `u16::MAX` devices.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encoder.put_point(self.identity.point());
        encoder.put_point(self.member.point());
        encode_key_epoch(&mut encoder, self.epoch);
        encoder.put_u16(count_u16(self.inner.participants().len())?);
        for participant in self.inner.participants() {
            encoder.put_fixed(participant.device().as_bytes());
            encoder.put_scalar(&participant.node().scalar());
            encoder.put_element(participant.share().element());
            encoder.put_scalar(&self.inner.coefficient(participant.device())?.scalar());
        }
        encoder.put_fixed(self.outer.person().as_bytes());
        encoder.put_u16(self.outer.slot().get());
        encoder.put_scalar(&self.outer.scalar());
        Ok(encoder.finish())
    }

    /// Returns the stable identity key.
    #[must_use]
    pub const fn identity(&self) -> IdentityKey<P> {
        self.identity
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member(&self) -> MemberPoint<P> {
        self.member
    }

    /// Returns the bound epochs and activation handles.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// Returns the accepted device support.
    #[must_use]
    pub const fn inner_support(&self) -> &InnerSupport<P> {
        &self.inner
    }

    /// Returns the accepted outer coefficient.
    #[must_use]
    pub const fn outer_coefficient(&self) -> OuterCoefficient<P> {
        self.outer
    }
}

/// A public commitment to one member body.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemberRecord<P: Profile = DefaultProfile> {
    slot: Slot,
    member: MemberPoint<P>,
    commitment: ScalarFor<P>,
}

impl<P: Profile> MemberRecord<P> {
    /// Commits to a private member body.
    ///
    /// # Errors
    ///
    /// Returns an error when body encoding or hash-to-field fails.
    pub fn commit(body: &MemberBody<P>, salt: &SecretScalar<P>) -> Result<Self> {
        let body_bytes = body.to_bytes()?;
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encoder.put_bytes(b"member")?;
        salt.expose(|value| encoder.put_scalar(value));
        encoder.put_bytes(&body_bytes)?;
        Ok(Self {
            slot: body.outer.slot(),
            member: body.member,
            commitment: hash::to_scalar_for::<P>(Domain::Member, &encoder.finish())?,
        })
    }

    /// Decodes a record.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let record = decode_record(&mut decoder)?;
        decoder.finish()?;
        Ok(record)
    }

    /// Returns the canonical record bytes.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encode_record(&mut encoder, self);
        encoder.finish()
    }

    /// Returns the outer slot.
    #[must_use]
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member(self) -> MemberPoint<P> {
        self.member
    }

    /// Returns the commitment scalar.
    #[must_use]
    pub const fn commitment(self) -> ScalarFor<P> {
        self.commitment
    }
}

impl<P: Profile> fmt::Debug for MemberRecord<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemberRecord")
            .field("slot", &self.slot)
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

/// Public values shared by one root package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootContext {
    vault: VaultId,
    epoch: OuterEpoch,
    ceremony: CommandId,
}

impl RootContext {
    /// Creates a root context.
    #[must_use]
    pub const fn new(vault: VaultId, epoch: OuterEpoch, ceremony: CommandId) -> Self {
        Self {
            vault,
            epoch,
            ceremony,
        }
    }

    /// Returns the vault identifier.
    #[must_use]
    pub const fn vault(self) -> VaultId {
        self.vault
    }

    /// Returns the outer epoch.
    #[must_use]
    pub const fn epoch(self) -> OuterEpoch {
        self.epoch
    }

    /// Returns the ceremony identifier.
    #[must_use]
    pub const fn ceremony(self) -> CommandId {
        self.ceremony
    }
}

/// One public root-package slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEntry<P: Profile = DefaultProfile> {
    record: MemberRecord<P>,
    nonce: NoncePair<P>,
}

/// One member nonce used to finalize a root package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberNonce<P: Profile = DefaultProfile> {
    slot: Slot,
    nonce: NoncePair<P>,
}

impl<P: Profile> MemberNonce<P> {
    /// Creates a member nonce.
    #[must_use]
    pub const fn new(slot: Slot, nonce: NoncePair<P>) -> Self {
        Self { slot, nonce }
    }

    /// Returns the outer slot.
    #[must_use]
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// Returns the public nonce pair.
    #[must_use]
    pub const fn nonce(self) -> NoncePair<P> {
        self.nonce
    }
}

/// A root package before nonce creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPrepackage<P: Profile = DefaultProfile> {
    key: VaultKey<P>,
    message: Vec<u8>,
    context: RootContext,
    records: Vec<MemberRecord<P>>,
}

impl<P: Profile> RootPrepackage<P> {
    /// Creates a prepackage bound to an accepted outer support.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, duplicate, or mismatched support.
    pub fn new(
        key: VaultKey<P>,
        message: Vec<u8>,
        context: RootContext,
        outer_support: &OuterSupport<P>,
        mut records: Vec<MemberRecord<P>>,
    ) -> Result<Self> {
        if records.is_empty() {
            return Err(Error::EmptyInput);
        }
        records.sort_unstable_by_key(|record| record.slot);
        reject_duplicate_records(&records)?;
        let prepackage = Self {
            key,
            message,
            context,
            records,
        };
        prepackage.validate_support(outer_support)?;
        prepackage.to_bytes()?;
        Ok(prepackage)
    }

    /// Decodes a root prepackage.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsorted, or duplicate fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let key = VaultKey::new(decoder.get_point()?);
        let message = decoder.get_bytes()?.to_vec();
        decode_protocol(&mut decoder)?;
        let context = decode_root_context(&mut decoder)?;
        let count = usize::from(decoder.get_u16()?);
        if count == 0 {
            return Err(Error::EmptyInput);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(decode_record(&mut decoder)?);
        }
        decoder.finish()?;
        ensure_sorted_records(&records)?;
        Ok(Self {
            key,
            message,
            context,
            records,
        })
    }

    /// Returns canonical prepackage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for oversized fields.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::<P>::for_profile();
        encode_root_prefix(&mut encoder, self.key, &self.message, self.context)?;
        encoder.put_u16(count_u16(self.records.len())?);
        for record in &self.records {
            encode_record(&mut encoder, *record);
        }
        Ok(encoder.finish())
    }

    /// Checks the records against an accepted outer support.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SupportMismatch`] when the supports differ.
    pub fn validate_support(&self, support: &OuterSupport<P>) -> Result<()> {
        if self.records.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        for (record, participant) in self.records.iter().zip(support.participants()) {
            if record.slot != participant.slot() || record.member != participant.member() {
                return Err(Error::SupportMismatch);
            }
        }
        Ok(())
    }

    /// Returns one slot's member record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the slot is absent.
    pub fn record(&self, slot: Slot) -> Result<MemberRecord<P>> {
        self.records
            .binary_search_by_key(&slot, |record| record.slot)
            .map(|index| self.records[index])
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the vault key.
    #[must_use]
    pub const fn key(&self) -> VaultKey<P> {
        self.key
    }

    /// Returns the signed message.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the root context.
    #[must_use]
    pub const fn context(&self) -> RootContext {
        self.context
    }

    /// Returns the sorted member records.
    #[must_use]
    pub fn records(&self) -> &[MemberRecord<P>] {
        &self.records
    }
}

impl<P: Profile> RootEntry<P> {
    /// Creates a root entry.
    #[must_use]
    pub const fn new(record: MemberRecord<P>, nonce: NoncePair<P>) -> Self {
        Self { record, nonce }
    }

    /// Returns the member record.
    #[must_use]
    pub const fn record(self) -> MemberRecord<P> {
        self.record
    }

    /// Returns the member nonce pair.
    #[must_use]
    pub const fn nonce(self) -> NoncePair<P> {
        self.nonce
    }
}

/// A canonical public signing package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPackage<P: Profile = DefaultProfile> {
    key: VaultKey<P>,
    message: Vec<u8>,
    context: RootContext,
    entries: Vec<RootEntry<P>>,
}

impl<P: Profile> RootPackage<P> {
    /// Creates a package bound to an accepted outer support.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, duplicate, or mismatched support.
    pub fn new(
        key: VaultKey<P>,
        message: Vec<u8>,
        context: RootContext,
        outer_support: &OuterSupport<P>,
        entries: Vec<RootEntry<P>>,
    ) -> Result<Self> {
        let (records, nonces) = entries
            .into_iter()
            .map(|entry| {
                (
                    entry.record,
                    MemberNonce::new(entry.record.slot, entry.nonce),
                )
            })
            .unzip();
        Self::finalize(
            RootPrepackage::new(key, message, context, outer_support, records)?,
            outer_support,
            nonces,
        )
    }

    /// Adds member nonces to a prepackage.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate, missing, or mismatched slot.
    pub fn finalize(
        prepackage: RootPrepackage<P>,
        outer_support: &OuterSupport<P>,
        mut nonces: Vec<MemberNonce<P>>,
    ) -> Result<Self> {
        prepackage.validate_support(outer_support)?;
        nonces.sort_unstable_by_key(|entry| entry.slot);
        if nonces.len() != prepackage.records.len() {
            return Err(Error::SupportMismatch);
        }
        for pair in nonces.windows(2) {
            if pair[0].slot == pair[1].slot {
                return Err(Error::DuplicateSlot);
            }
        }
        let entries = prepackage
            .records
            .iter()
            .zip(nonces)
            .map(|(record, nonce)| {
                if record.slot != nonce.slot {
                    return Err(Error::SupportMismatch);
                }
                Ok(RootEntry::new(*record, nonce.nonce))
            })
            .collect::<Result<Vec<_>>>()?;
        let package = Self {
            key: prepackage.key,
            message: prepackage.message,
            context: prepackage.context,
            entries,
        };
        package.to_bytes()?;
        Ok(package)
    }

    /// Decodes a public root package.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsorted, or inconsistent fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let key = VaultKey::new(decoder.get_point()?);
        let message = decoder.get_bytes()?.to_vec();
        decode_protocol(&mut decoder)?;
        let context = decode_root_context(&mut decoder)?;

        let public_count = usize::from(decoder.get_u16()?);
        if public_count == 0 {
            return Err(Error::EmptyInput);
        }
        let mut public = Vec::with_capacity(public_count);
        for _ in 0..public_count {
            public.push((
                Slot::new(decoder.get_u16()?),
                MemberPoint::new(decoder.get_point()?),
                NoncePair::new(decoder.get_point()?, decoder.get_point()?),
            ));
        }

        let record_count = usize::from(decoder.get_u16()?);
        if public_count != record_count {
            return Err(Error::LengthMismatch);
        }
        let mut entries = Vec::with_capacity(record_count);
        for (slot, member, nonce) in public {
            let record = decode_record(&mut decoder)?;
            if record.slot != slot || record.member != member {
                return Err(Error::InvalidTranscript);
            }
            entries.push(RootEntry::new(record, nonce));
        }
        decoder.finish()?;
        ensure_sorted_slots(&entries)?;
        Ok(Self {
            key,
            message,
            context,
            entries,
        })
    }

    /// Returns the canonical package bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for oversized fields.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::<P>::for_profile();
        encode_root_prefix(&mut encoder, self.key, &self.message, self.context)?;
        encoder.put_u16(count_u16(self.entries.len())?);
        for entry in &self.entries {
            encoder.put_u16(entry.record.slot.get());
            encoder.put_point(entry.record.member.point());
            encoder.put_point(entry.nonce.hiding());
            encoder.put_point(entry.nonce.binding());
        }
        encoder.put_u16(count_u16(self.entries.len())?);
        for entry in &self.entries {
            encode_record(&mut encoder, entry.record);
        }
        Ok(encoder.finish())
    }

    /// Checks the package against an accepted outer support.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SupportMismatch`] when the supports differ.
    pub fn validate_support(&self, support: &OuterSupport<P>) -> Result<()> {
        if self.entries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        for (entry, participant) in self.entries.iter().zip(support.participants()) {
            if entry.record.slot != participant.slot()
                || entry.record.member != participant.member()
            {
                return Err(Error::SupportMismatch);
            }
        }
        Ok(())
    }

    /// Returns one slot's entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the slot is absent.
    pub fn entry(&self, slot: Slot) -> Result<RootEntry<P>> {
        self.entries
            .binary_search_by_key(&slot, |entry| entry.record.slot)
            .map(|index| self.entries[index])
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the vault key.
    #[must_use]
    pub const fn key(&self) -> VaultKey<P> {
        self.key
    }

    /// Returns the signed message.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the root context.
    #[must_use]
    pub const fn context(&self) -> RootContext {
        self.context
    }

    /// Returns the sorted root entries.
    #[must_use]
    pub fn entries(&self) -> &[RootEntry<P>] {
        &self.entries
    }

    /// Returns the exact pre-nonce package.
    #[must_use]
    pub fn prepackage(&self) -> RootPrepackage<P> {
        RootPrepackage {
            key: self.key,
            message: self.message.clone(),
            context: self.context,
            records: self.entries.iter().map(|entry| entry.record).collect(),
        }
    }

    fn binding_preimage(&self, slot: Slot) -> Result<Vec<u8>> {
        let index = self
            .entries
            .binary_search_by_key(&slot, |entry| entry.record.slot)
            .map_err(|_| Error::ParticipantNotFound)?;
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encoder.put_bytes(&self.to_bytes()?)?;
        encoder.put_u16(count_u16(index)?);
        Ok(encoder.finish())
    }
}

/// A private member opening.
pub struct MemberOpening<P: Profile = DefaultProfile> {
    salt: SecretScalar<P>,
    body: MemberBody<P>,
}

impl<P: Profile> MemberOpening<P> {
    /// Creates an opening with a supplied salt.
    ///
    /// Use [`Self::sample`] for live sessions.
    #[must_use]
    pub const fn new(salt: SecretScalar<P>, body: MemberBody<P>) -> Self {
        Self { salt, body }
    }

    /// Samples a fresh commitment salt.
    #[must_use]
    pub fn sample(
        body: MemberBody<P>,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Self {
        Self {
            salt: SecretScalar::new(FieldOf::<P>::random(rng)),
            body,
        }
    }

    /// Decodes a private member opening.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or a support mismatch.
    pub fn from_bytes(bytes: &[u8], outer_support: &OuterSupport<P>) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let salt = SecretScalar::new(decoder.get_scalar()?);
        let body = MemberBody::from_bytes(decoder.get_bytes()?, outer_support)?;
        decoder.finish()?;
        Ok(Self { salt, body })
    }

    /// Returns canonical private bytes in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized body.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        self.salt.expose(|value| encoder.put_scalar(value));
        encoder.put_bytes(&self.body.to_bytes()?)?;
        Ok(Zeroizing::new(encoder.finish()))
    }

    /// Returns the member body.
    #[must_use]
    pub const fn body(&self) -> &MemberBody<P> {
        &self.body
    }

    /// Computes the matching public record.
    ///
    /// # Errors
    ///
    /// Returns an error when body encoding or hash-to-field fails.
    pub fn record(&self) -> Result<MemberRecord<P>> {
        MemberRecord::commit(&self.body, &self.salt)
    }
}

/// A verified private member reservation before nonce creation.
pub struct MemberReservation<P: Profile = DefaultProfile> {
    prepackage: RootPrepackage<P>,
    opening: MemberOpening<P>,
}

impl<P: Profile> MemberReservation<P> {
    /// Verifies a prepackage and one private opening.
    ///
    /// # Errors
    ///
    /// Returns an error for a support, epoch, handle, or commitment mismatch.
    pub fn new(
        prepackage: RootPrepackage<P>,
        opening: MemberOpening<P>,
        outer_support: &OuterSupport<P>,
    ) -> Result<Self> {
        prepackage.validate_support(outer_support)?;
        let body = opening.body();
        if body.epoch.outer() != prepackage.context.epoch
            || body.epoch.anchor().vault() != prepackage.context.vault
        {
            return Err(Error::InvalidTranscript);
        }
        if prepackage.record(body.outer.slot())? != opening.record()? {
            return Err(Error::CommitmentMismatch);
        }
        Ok(Self {
            prepackage,
            opening,
        })
    }

    /// Decodes exact reservation bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or a transcript mismatch.
    pub fn from_bytes(
        bytes: &[u8],
        outer_support: &OuterSupport<P>,
    ) -> Result<(Self, SessionId, u64)> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let prepackage = RootPrepackage::from_bytes(decoder.get_bytes()?)?;
        let slot = Slot::new(decoder.get_u16()?);
        let opening = MemberOpening::from_bytes(decoder.get_bytes()?, outer_support)?;
        let session = SessionId::new(decoder.get_fixed()?);
        let expiry = decoder.get_u64()?;
        decoder.finish()?;
        let reservation = Self::new(prepackage, opening, outer_support)?;
        if reservation.slot() != slot {
            return Err(Error::InvalidTranscript);
        }
        Ok((reservation, session, expiry))
    }

    /// Returns exact reservation bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized field.
    pub fn to_bytes(&self, session: SessionId, expiry: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encoder.put_bytes(&self.prepackage.to_bytes()?)?;
        encoder.put_u16(self.slot().get());
        encoder.put_bytes(&self.opening.to_bytes()?)?;
        encoder.put_fixed(session.as_bytes());
        encoder.put_u64(expiry);
        Ok(Zeroizing::new(encoder.finish()))
    }

    /// Returns the public prepackage.
    #[must_use]
    pub const fn prepackage(&self) -> &RootPrepackage<P> {
        &self.prepackage
    }

    /// Returns the private member body.
    #[must_use]
    pub const fn body(&self) -> &MemberBody<P> {
        self.opening.body()
    }

    /// Returns the selected outer slot.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.opening.body.outer.slot()
    }
}

/// A verified root package and private member opening.
pub struct MemberTranscript<P: Profile = DefaultProfile> {
    root: RootPackage<P>,
    opening: MemberOpening<P>,
}

impl<P: Profile> MemberTranscript<P> {
    /// Verifies and joins a root package with one private opening.
    ///
    /// # Errors
    ///
    /// Returns an error for a support, epoch, handle, or commitment mismatch.
    pub fn new(
        root: RootPackage<P>,
        opening: MemberOpening<P>,
        outer_support: &OuterSupport<P>,
    ) -> Result<Self> {
        let reservation = MemberReservation::new(root.prepackage(), opening, outer_support)?;
        Self::finalize(root, reservation)
    }

    /// Joins a finalized root with its exact reservation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTranscript`] when the prepackage changed.
    pub fn finalize(root: RootPackage<P>, reservation: MemberReservation<P>) -> Result<Self> {
        if root.prepackage() != reservation.prepackage {
            return Err(Error::InvalidTranscript);
        }
        Ok(Self {
            root,
            opening: reservation.opening,
        })
    }

    /// Returns the public root package.
    #[must_use]
    pub const fn root(&self) -> &RootPackage<P> {
        &self.root
    }

    /// Returns the private member body.
    #[must_use]
    pub const fn body(&self) -> &MemberBody<P> {
        self.opening.body()
    }

    /// Returns the selected outer slot.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.opening.body.outer.slot()
    }
}

/// Hashes derived from one finalized root package.
pub struct SigningContext<'a, P: Profile = DefaultProfile> {
    root: &'a RootPackage<P>,
    bindings: Vec<(Slot, ScalarFor<P>)>,
    nonce: Point<P>,
    challenge: ScalarFor<P>,
}

impl<'a, P: Profile> SigningContext<'a, P> {
    /// Derives all binding factors, the aggregate nonce, and the challenge.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hash input or identity nonce sum.
    pub fn new(root: &'a RootPackage<P>) -> Result<Self> {
        let mut bindings = Vec::with_capacity(root.entries.len());
        let mut pairs = Vec::with_capacity(root.entries.len());
        for entry in &root.entries {
            let slot = entry.record.slot;
            let binding = signing::binding_factor::<P>(&root.binding_preimage(slot)?)?;
            bindings.push((slot, binding));
            pairs.push((entry.nonce, binding));
        }
        let nonce = signing::aggregate_nonce(&pairs)?;
        let challenge = signing::challenge(nonce, root.key, &root.message)?;
        Ok(Self {
            root,
            bindings,
            nonce,
            challenge,
        })
    }

    /// Returns one slot's binding factor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the slot is absent.
    pub fn binding(&self, slot: Slot) -> Result<ScalarFor<P>> {
        self.bindings
            .binary_search_by_key(&slot, |(entry_slot, _)| *entry_slot)
            .map(|index| self.bindings[index].1)
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the root package.
    #[must_use]
    pub const fn root(&self) -> &'a RootPackage<P> {
        self.root
    }

    /// Returns the aggregate nonce.
    #[must_use]
    pub const fn nonce(&self) -> Point<P> {
        self.nonce
    }

    /// Returns the Schnorr challenge.
    #[must_use]
    pub const fn challenge(&self) -> ScalarFor<P> {
        self.challenge
    }
}

fn expect_version<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<()> {
    if decoder.get_u8()? == P::WIRE_ID {
        Ok(())
    } else {
        Err(Error::UnsupportedVersion)
    }
}

fn count_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::LengthOverflow)
}

fn encode_root_prefix<P: Profile>(
    encoder: &mut Encoder<P>,
    key: VaultKey<P>,
    message: &[u8],
    context: RootContext,
) -> Result<()> {
    encoder.put_u8(P::WIRE_ID);
    encoder.put_point(key.point());
    encoder.put_bytes(message)?;
    encoder.put_bytes(P::PROTOCOL_ID)?;
    encoder.put_fixed(context.vault.as_bytes());
    encoder.put_u64(context.epoch.get());
    encoder.put_fixed(context.ceremony.as_bytes());
    Ok(())
}

fn decode_protocol<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<()> {
    if decoder.get_bytes()? == P::PROTOCOL_ID {
        Ok(())
    } else {
        Err(Error::ProtocolMismatch)
    }
}

fn decode_root_context<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<RootContext> {
    Ok(RootContext::new(
        VaultId::new(decoder.get_fixed()?),
        OuterEpoch::new(decoder.get_u64()?),
        CommandId::new(decoder.get_fixed()?),
    ))
}

fn encode_key_epoch<P: Profile>(encoder: &mut Encoder<P>, epoch: KeyEpoch) {
    encoder.put_u64(epoch.outer().get());
    encoder.put_u64(epoch.inner().get());
    let anchor = epoch.anchor();
    encoder.put_fixed(anchor.vault().as_bytes());
    encoder.put_fixed(anchor.person().as_bytes());
    encoder.put_fixed(anchor.identity().as_bytes());
    encoder.put_fixed(anchor.member().as_bytes());
}

fn decode_key_epoch<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<KeyEpoch> {
    let outer = OuterEpoch::new(decoder.get_u64()?);
    let inner = InnerEpoch::new(decoder.get_u64()?);
    let anchor = AnchorId::new(
        VaultId::new(decoder.get_fixed()?),
        PersonId::new(decoder.get_fixed()?),
        ActivationHandle::new(decoder.get_fixed()?),
        ActivationHandle::new(decoder.get_fixed()?),
    );
    Ok(KeyEpoch::new(outer, inner, anchor))
}

fn encode_record<P: Profile>(encoder: &mut Encoder<P>, record: MemberRecord<P>) {
    encoder.put_u16(record.slot.get());
    encoder.put_point(record.member.point());
    encoder.put_scalar(&record.commitment);
}

fn decode_record<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<MemberRecord<P>> {
    Ok(MemberRecord {
        slot: Slot::new(decoder.get_u16()?),
        member: MemberPoint::new(decoder.get_point()?),
        commitment: decoder.get_scalar()?,
    })
}

fn reject_duplicate_records<P: Profile>(records: &[MemberRecord<P>]) -> Result<()> {
    for pair in records.windows(2) {
        if pair[0].slot == pair[1].slot {
            return Err(Error::DuplicateSlot);
        }
    }
    Ok(())
}

fn ensure_sorted_records<P: Profile>(records: &[MemberRecord<P>]) -> Result<()> {
    for pair in records.windows(2) {
        if pair[0].slot >= pair[1].slot {
            return Err(if pair[0].slot == pair[1].slot {
                Error::DuplicateSlot
            } else {
                Error::InvalidTranscript
            });
        }
    }
    Ok(())
}

fn ensure_sorted_slots<P: Profile>(entries: &[RootEntry<P>]) -> Result<()> {
    for pair in entries.windows(2) {
        if pair[0].record.slot >= pair[1].record.slot {
            return Err(if pair[0].record.slot == pair[1].record.slot {
                Error::DuplicateSlot
            } else {
                Error::InvalidTranscript
            });
        }
    }
    Ok(())
}
