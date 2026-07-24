//! Accepted signing supports.

use core::fmt;

use crate::algebra::ScalarFor;
use crate::keys::{MemberPoint, SharePoint};
use crate::profile::{DefaultProfile, Profile};
use crate::shamir::{Node, lagrange_at_zero};
use crate::types::{DeviceId, PersonId, Slot};
use crate::{Error, Result};

/// A device in one accepted inner support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceParticipant<P: Profile = DefaultProfile> {
    device: DeviceId,
    node: Node<P>,
    share: SharePoint<P>,
}

impl<P: Profile> DeviceParticipant<P> {
    /// Creates a device participant.
    #[must_use]
    pub const fn new(device: DeviceId, node: Node<P>, share: SharePoint<P>) -> Self {
        Self {
            device,
            node,
            share,
        }
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the Shamir node.
    #[must_use]
    pub const fn node(self) -> Node<P> {
        self.node
    }

    /// Returns the public share point.
    #[must_use]
    pub const fn share(self) -> SharePoint<P> {
        self.share
    }
}

/// A person in one accepted outer support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonParticipant<P: Profile = DefaultProfile> {
    person: PersonId,
    slot: Slot,
    node: Node<P>,
    member: MemberPoint<P>,
}

impl<P: Profile> PersonParticipant<P> {
    /// Creates a person participant.
    #[must_use]
    pub const fn new(person: PersonId, slot: Slot, node: Node<P>, member: MemberPoint<P>) -> Self {
        Self {
            person,
            slot,
            node,
            member,
        }
    }

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(self) -> PersonId {
        self.person
    }

    /// Returns the outer slot.
    #[must_use]
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// Returns the Shamir node.
    #[must_use]
    pub const fn node(self) -> Node<P> {
        self.node
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member(self) -> MemberPoint<P> {
        self.member
    }
}

/// A device's inner Lagrange coefficient.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InnerCoefficient<P: Profile = DefaultProfile> {
    device: DeviceId,
    scalar: ScalarFor<P>,
}

impl<P: Profile> InnerCoefficient<P> {
    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the coefficient scalar.
    #[must_use]
    pub const fn scalar(self) -> ScalarFor<P> {
        self.scalar
    }
}

impl<P: Profile> fmt::Debug for InnerCoefficient<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InnerCoefficient")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

/// A person's outer Lagrange coefficient.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OuterCoefficient<P: Profile = DefaultProfile> {
    person: PersonId,
    slot: Slot,
    member: MemberPoint<P>,
    scalar: ScalarFor<P>,
}

/// A source role's coefficient in one accepted support.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SourceWeight<P: Profile = DefaultProfile> {
    device: DeviceId,
    scalar: ScalarFor<P>,
}

impl<P: Profile> SourceWeight<P> {
    /// Returns the source device.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the source coefficient.
    #[must_use]
    pub const fn scalar(self) -> ScalarFor<P> {
        self.scalar
    }
}

impl<P: Profile> fmt::Debug for SourceWeight<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceWeight")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl<P: Profile> OuterCoefficient<P> {
    /// Returns the person identifier.
    #[must_use]
    pub const fn person(self) -> PersonId {
        self.person
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

    /// Returns the coefficient scalar.
    #[must_use]
    pub const fn scalar(self) -> ScalarFor<P> {
        self.scalar
    }
}

impl<P: Profile> fmt::Debug for OuterCoefficient<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OuterCoefficient")
            .field("person", &self.person)
            .field("slot", &self.slot)
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

/// A canonical accepted device support.
#[derive(Clone, Eq, PartialEq)]
pub struct InnerSupport<P: Profile = DefaultProfile> {
    participants: Vec<DeviceParticipant<P>>,
    coefficients: Vec<ScalarFor<P>>,
}

impl<P: Profile> InnerSupport<P> {
    /// Creates a support sorted by device identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty support, duplicate device, or duplicate
    /// Shamir node.
    pub fn new(mut participants: Vec<DeviceParticipant<P>>) -> Result<Self> {
        if participants.is_empty() {
            return Err(Error::EmptyInput);
        }
        participants.sort_unstable_by_key(|participant| participant.device);
        reject_duplicate_devices(&participants)?;
        let nodes = participants
            .iter()
            .map(|participant| participant.node)
            .collect::<Vec<_>>();
        let coefficients = lagrange_at_zero(&nodes)?;
        Ok(Self {
            participants,
            coefficients,
        })
    }

    /// Returns the sorted participants.
    #[must_use]
    pub fn participants(&self) -> &[DeviceParticipant<P>] {
        &self.participants
    }

    /// Returns one device's coefficient.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the device is absent.
    pub fn coefficient(&self, device: DeviceId) -> Result<InnerCoefficient<P>> {
        let index = self
            .participants
            .binary_search_by_key(&device, |participant| participant.device)
            .map_err(|_| Error::ParticipantNotFound)?;
        Ok(InnerCoefficient {
            device,
            scalar: self.coefficients[index],
        })
    }

    /// Returns one device participant.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the device is absent.
    pub fn participant(&self, device: DeviceId) -> Result<DeviceParticipant<P>> {
        self.participants
            .binary_search_by_key(&device, |participant| participant.device)
            .map(|index| self.participants[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

impl<P: Profile> fmt::Debug for InnerSupport<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InnerSupport")
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

/// A canonical accepted person support.
#[derive(Clone, Eq, PartialEq)]
pub struct OuterSupport<P: Profile = DefaultProfile> {
    participants: Vec<PersonParticipant<P>>,
    coefficients: Vec<ScalarFor<P>>,
}

impl<P: Profile> OuterSupport<P> {
    /// Creates a support sorted by outer slot.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty support or duplicate person, slot, or
    /// Shamir node.
    pub fn new(mut participants: Vec<PersonParticipant<P>>) -> Result<Self> {
        if participants.is_empty() {
            return Err(Error::EmptyInput);
        }
        participants.sort_unstable_by_key(|participant| participant.slot);
        reject_duplicate_people(&participants)?;
        let nodes = participants
            .iter()
            .map(|participant| participant.node)
            .collect::<Vec<_>>();
        let coefficients = lagrange_at_zero(&nodes)?;
        Ok(Self {
            participants,
            coefficients,
        })
    }

    /// Returns the sorted participants.
    #[must_use]
    pub fn participants(&self) -> &[PersonParticipant<P>] {
        &self.participants
    }

    /// Returns one person's coefficient.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the person is absent.
    pub fn coefficient(&self, person: PersonId) -> Result<OuterCoefficient<P>> {
        let index = self
            .participants
            .iter()
            .position(|participant| participant.person == person)
            .ok_or(Error::ParticipantNotFound)?;
        let participant = self.participants[index];
        Ok(OuterCoefficient {
            person,
            slot: participant.slot,
            member: participant.member,
            scalar: self.coefficients[index],
        })
    }

    /// Returns one slot's participant.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the slot is absent.
    pub fn participant(&self, slot: Slot) -> Result<PersonParticipant<P>> {
        self.participants
            .binary_search_by_key(&slot, |participant| participant.slot)
            .map(|index| self.participants[index])
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Derives one device's composed outer and inner source coefficient.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when either participant is
    /// absent.
    pub fn source_weight(
        &self,
        person: PersonId,
        inner: &InnerSupport<P>,
        device: DeviceId,
    ) -> Result<SourceWeight<P>> {
        Ok(SourceWeight {
            device,
            scalar: self.coefficient(person)?.scalar() * inner.coefficient(device)?.scalar(),
        })
    }
}

impl<P: Profile> fmt::Debug for OuterSupport<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OuterSupport")
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

impl<P: Profile> InnerSupport<P> {
    /// Derives one device's inner source coefficient.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the device is absent.
    pub fn source_weight(&self, device: DeviceId) -> Result<SourceWeight<P>> {
        Ok(SourceWeight {
            device,
            scalar: self.coefficient(device)?.scalar(),
        })
    }
}

fn reject_duplicate_devices<P: Profile>(participants: &[DeviceParticipant<P>]) -> Result<()> {
    for (index, participant) in participants.iter().enumerate() {
        if participants[..index]
            .iter()
            .any(|prior| prior.device == participant.device)
        {
            return Err(Error::DuplicateParticipant);
        }
    }
    Ok(())
}

fn reject_duplicate_people<P: Profile>(participants: &[PersonParticipant<P>]) -> Result<()> {
    for (index, participant) in participants.iter().enumerate() {
        if participants[..index]
            .iter()
            .any(|prior| prior.slot == participant.slot)
        {
            return Err(Error::DuplicateSlot);
        }
        if participants[..index]
            .iter()
            .any(|prior| prior.person == participant.person)
        {
            return Err(Error::DuplicateParticipant);
        }
    }
    Ok(())
}
