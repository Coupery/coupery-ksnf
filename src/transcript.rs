//! Canonical signing transcripts.

use zeroize::Zeroizing;

use crate::algebra::{Scalar, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::hash::{self, Domain};
use crate::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
use crate::shamir::Node;
use crate::signing::{self, NoncePair};
use crate::support::{DeviceParticipant, InnerSupport, OuterCoefficient, OuterSupport};
use crate::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, Slot, VaultId,
};
use crate::{Error, Result};

const VERSION: u8 = 1;

/// The fixed protocol identifier.
pub const PROTOCOL_ID: &[u8] = b"coupery-ksnf/v1";

/// A private member commitment body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberBody {
    identity: IdentityKey,
    member: MemberPoint,
    epoch: KeyEpoch,
    inner: InnerSupport,
    outer: OuterCoefficient,
}

impl MemberBody {
    /// Creates a body from accepted supports.
    ///
    /// # Errors
    ///
    /// Returns an error when its person or member values disagree.
    pub fn new(
        identity: IdentityKey,
        member: MemberPoint,
        epoch: KeyEpoch,
        inner: InnerSupport,
        outer: OuterCoefficient,
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
    pub fn from_bytes(bytes: &[u8], outer_support: &OuterSupport) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
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
                SharePoint::new(decoder.get_point()?),
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
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        encoder.put_point(self.identity.point());
        encoder.put_point(self.member.point());
        encode_key_epoch(&mut encoder, self.epoch);
        encoder.put_u16(count_u16(self.inner.participants().len())?);
        for participant in self.inner.participants() {
            encoder.put_fixed(participant.device().as_bytes());
            encoder.put_scalar(&participant.node().scalar());
            encoder.put_point(participant.share().point());
            encoder.put_scalar(&self.inner.coefficient(participant.device())?.scalar());
        }
        encoder.put_fixed(self.outer.person().as_bytes());
        encoder.put_u16(self.outer.slot().get());
        encoder.put_scalar(&self.outer.scalar());
        Ok(encoder.finish())
    }

    /// Returns the stable identity key.
    #[must_use]
    pub const fn identity(&self) -> IdentityKey {
        self.identity
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member(&self) -> MemberPoint {
        self.member
    }

    /// Returns the bound epochs and activation handles.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// Returns the accepted device support.
    #[must_use]
    pub const fn inner_support(&self) -> &InnerSupport {
        &self.inner
    }

    /// Returns the accepted outer coefficient.
    #[must_use]
    pub const fn outer_coefficient(&self) -> OuterCoefficient {
        self.outer
    }
}

/// A public commitment to one member body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberRecord {
    slot: Slot,
    member: MemberPoint,
    commitment: Scalar,
}

impl MemberRecord {
    /// Commits to a private member body.
    ///
    /// # Errors
    ///
    /// Returns an error when body encoding or hash-to-field fails.
    pub fn commit(body: &MemberBody, salt: &SecretScalar) -> Result<Self> {
        let body_bytes = body.to_bytes()?;
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        encoder.put_bytes(b"member")?;
        salt.expose(|value| encoder.put_scalar(value));
        encoder.put_bytes(&body_bytes)?;
        Ok(Self {
            slot: body.outer.slot(),
            member: body.member,
            commitment: hash::to_scalar(Domain::Member, &encoder.finish())?,
        })
    }

    /// Decodes a record.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        expect_version(&mut decoder)?;
        let record = decode_record(&mut decoder)?;
        decoder.finish()?;
        Ok(record)
    }

    /// Returns the canonical record bytes.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
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
    pub const fn member(self) -> MemberPoint {
        self.member
    }

    /// Returns the commitment scalar.
    #[must_use]
    pub const fn commitment(self) -> Scalar {
        self.commitment
    }
}

/// Public values shared by one root package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootContext {
    vault: VaultId,
    epoch: OuterEpoch,
    command: CommandId,
}

impl RootContext {
    /// Creates a root context.
    #[must_use]
    pub const fn new(vault: VaultId, epoch: OuterEpoch, command: CommandId) -> Self {
        Self {
            vault,
            epoch,
            command,
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
    pub const fn command(self) -> CommandId {
        self.command
    }
}

/// One public root-package slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEntry {
    record: MemberRecord,
    nonce: NoncePair,
}

impl RootEntry {
    /// Creates a root entry.
    #[must_use]
    pub const fn new(record: MemberRecord, nonce: NoncePair) -> Self {
        Self { record, nonce }
    }

    /// Returns the member record.
    #[must_use]
    pub const fn record(self) -> MemberRecord {
        self.record
    }

    /// Returns the member nonce pair.
    #[must_use]
    pub const fn nonce(self) -> NoncePair {
        self.nonce
    }
}

/// A canonical public signing package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPackage {
    key: VaultKey,
    message: Vec<u8>,
    context: RootContext,
    entries: Vec<RootEntry>,
}

impl RootPackage {
    /// Creates a package bound to an accepted outer support.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, duplicate, or mismatched support.
    pub fn new(
        key: VaultKey,
        message: Vec<u8>,
        context: RootContext,
        outer_support: &OuterSupport,
        mut entries: Vec<RootEntry>,
    ) -> Result<Self> {
        if entries.is_empty() {
            return Err(Error::EmptyInput);
        }
        entries.sort_unstable_by_key(|entry| entry.record.slot);
        reject_duplicate_slots(&entries)?;
        let package = Self {
            key,
            message,
            context,
            entries,
        };
        package.validate_support(outer_support)?;
        package.to_bytes()?;
        Ok(package)
    }

    /// Decodes a public root package.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsorted, or inconsistent fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        expect_version(&mut decoder)?;
        let key = VaultKey::new(decoder.get_point()?);
        let message = decoder.get_bytes()?.to_vec();
        let protocol = decoder.get_bytes()?;
        if protocol != PROTOCOL_ID {
            return Err(Error::ProtocolMismatch);
        }
        let context = RootContext::new(
            VaultId::new(decoder.get_fixed()?),
            OuterEpoch::new(decoder.get_u64()?),
            CommandId::new(decoder.get_fixed()?),
        );

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
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        encoder.put_point(self.key.point());
        encoder.put_bytes(&self.message)?;
        encoder.put_bytes(PROTOCOL_ID)?;
        encoder.put_fixed(self.context.vault.as_bytes());
        encoder.put_u64(self.context.epoch.get());
        encoder.put_fixed(self.context.command.as_bytes());
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
    pub fn validate_support(&self, support: &OuterSupport) -> Result<()> {
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
    pub fn entry(&self, slot: Slot) -> Result<RootEntry> {
        self.entries
            .binary_search_by_key(&slot, |entry| entry.record.slot)
            .map(|index| self.entries[index])
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the vault key.
    #[must_use]
    pub const fn key(&self) -> VaultKey {
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
    pub fn entries(&self) -> &[RootEntry] {
        &self.entries
    }

    fn binding_preimage(&self, slot: Slot) -> Result<Vec<u8>> {
        let index = self
            .entries
            .binary_search_by_key(&slot, |entry| entry.record.slot)
            .map_err(|_| Error::ParticipantNotFound)?;
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        encoder.put_bytes(&self.to_bytes()?)?;
        encoder.put_u16(count_u16(index)?);
        Ok(encoder.finish())
    }
}

/// A private member opening.
pub struct MemberOpening {
    salt: SecretScalar,
    body: MemberBody,
}

impl MemberOpening {
    /// Creates a private member opening.
    #[must_use]
    pub const fn new(salt: SecretScalar, body: MemberBody) -> Self {
        Self { salt, body }
    }

    /// Decodes a private member opening.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or a support mismatch.
    pub fn from_bytes(bytes: &[u8], outer_support: &OuterSupport) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
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
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        self.salt.expose(|value| encoder.put_scalar(value));
        encoder.put_bytes(&self.body.to_bytes()?)?;
        Ok(Zeroizing::new(encoder.finish()))
    }

    /// Returns the member body.
    #[must_use]
    pub const fn body(&self) -> &MemberBody {
        &self.body
    }

    /// Computes the matching public record.
    ///
    /// # Errors
    ///
    /// Returns an error when body encoding or hash-to-field fails.
    pub fn record(&self) -> Result<MemberRecord> {
        MemberRecord::commit(&self.body, &self.salt)
    }
}

/// A verified root package and private member opening.
pub struct MemberTranscript {
    root: RootPackage,
    opening: MemberOpening,
}

impl MemberTranscript {
    /// Verifies and joins a root package with one private opening.
    ///
    /// # Errors
    ///
    /// Returns an error for a support, epoch, handle, or commitment mismatch.
    pub fn new(
        root: RootPackage,
        opening: MemberOpening,
        outer_support: &OuterSupport,
    ) -> Result<Self> {
        root.validate_support(outer_support)?;
        let body = opening.body();
        if body.epoch.outer() != root.context.epoch
            || body.epoch.anchor().vault() != root.context.vault
        {
            return Err(Error::InvalidTranscript);
        }
        let record = root.entry(body.outer.slot())?.record;
        if record != opening.record()? {
            return Err(Error::CommitmentMismatch);
        }
        Ok(Self { root, opening })
    }

    /// Returns the public root package.
    #[must_use]
    pub const fn root(&self) -> &RootPackage {
        &self.root
    }

    /// Returns the private member body.
    #[must_use]
    pub const fn body(&self) -> &MemberBody {
        self.opening.body()
    }

    /// Returns the selected outer slot.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.opening.body.outer.slot()
    }
}

/// Hashes derived from one finalized root package.
pub struct SigningContext<'a> {
    root: &'a RootPackage,
    bindings: Vec<(Slot, Scalar)>,
    nonce: crate::algebra::Point,
    challenge: Scalar,
}

impl<'a> SigningContext<'a> {
    /// Derives all binding factors, the aggregate nonce, and the challenge.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hash input or identity nonce sum.
    pub fn new(root: &'a RootPackage) -> Result<Self> {
        let mut bindings = Vec::with_capacity(root.entries.len());
        let mut pairs = Vec::with_capacity(root.entries.len());
        for entry in &root.entries {
            let slot = entry.record.slot;
            let binding = signing::binding_factor(&root.binding_preimage(slot)?)?;
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
    pub fn binding(&self, slot: Slot) -> Result<Scalar> {
        self.bindings
            .binary_search_by_key(&slot, |(entry_slot, _)| *entry_slot)
            .map(|index| self.bindings[index].1)
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the root package.
    #[must_use]
    pub const fn root(&self) -> &'a RootPackage {
        self.root
    }

    /// Returns the aggregate nonce.
    #[must_use]
    pub const fn nonce(&self) -> crate::algebra::Point {
        self.nonce
    }

    /// Returns the Schnorr challenge.
    #[must_use]
    pub const fn challenge(&self) -> Scalar {
        self.challenge
    }
}

fn expect_version(decoder: &mut Decoder<'_>) -> Result<()> {
    if decoder.get_u8()? == VERSION {
        Ok(())
    } else {
        Err(Error::UnsupportedVersion)
    }
}

fn count_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::LengthOverflow)
}

fn encode_key_epoch(encoder: &mut Encoder, epoch: KeyEpoch) {
    encoder.put_u64(epoch.outer().get());
    encoder.put_u64(epoch.inner().get());
    let anchor = epoch.anchor();
    encoder.put_fixed(anchor.vault().as_bytes());
    encoder.put_fixed(anchor.person().as_bytes());
    encoder.put_fixed(anchor.identity().as_bytes());
    encoder.put_fixed(anchor.member().as_bytes());
}

fn decode_key_epoch(decoder: &mut Decoder<'_>) -> Result<KeyEpoch> {
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

fn encode_record(encoder: &mut Encoder, record: MemberRecord) {
    encoder.put_u16(record.slot.get());
    encoder.put_point(record.member.point());
    encoder.put_scalar(&record.commitment);
}

fn decode_record(decoder: &mut Decoder<'_>) -> Result<MemberRecord> {
    Ok(MemberRecord {
        slot: Slot::new(decoder.get_u16()?),
        member: MemberPoint::new(decoder.get_point()?),
        commitment: decoder.get_scalar()?,
    })
}

fn reject_duplicate_slots(entries: &[RootEntry]) -> Result<()> {
    for pair in entries.windows(2) {
        if pair[0].record.slot == pair[1].record.slot {
            return Err(Error::DuplicateSlot);
        }
    }
    Ok(())
}

fn ensure_sorted_slots(entries: &[RootEntry]) -> Result<()> {
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
