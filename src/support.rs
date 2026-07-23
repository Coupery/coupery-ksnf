//! Accepted signing supports.

use crate::algebra::Scalar;
use crate::keys::{MemberPoint, SharePoint};
use crate::shamir::{Node, lagrange_at_zero};
use crate::types::{DeviceId, PersonId, Slot};
use crate::{Error, Result};

/// A device in one accepted inner support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceParticipant {
    device: DeviceId,
    node: Node,
    share: SharePoint,
}

impl DeviceParticipant {
    /// Creates a device participant.
    #[must_use]
    pub const fn new(device: DeviceId, node: Node, share: SharePoint) -> Self {
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
    pub const fn node(self) -> Node {
        self.node
    }

    /// Returns the public share point.
    #[must_use]
    pub const fn share(self) -> SharePoint {
        self.share
    }
}

/// A person in one accepted outer support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonParticipant {
    person: PersonId,
    slot: Slot,
    node: Node,
    member: MemberPoint,
}

impl PersonParticipant {
    /// Creates a person participant.
    #[must_use]
    pub const fn new(person: PersonId, slot: Slot, node: Node, member: MemberPoint) -> Self {
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
    pub const fn node(self) -> Node {
        self.node
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member(self) -> MemberPoint {
        self.member
    }
}

/// A device's inner Lagrange coefficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerCoefficient {
    device: DeviceId,
    scalar: Scalar,
}

impl InnerCoefficient {
    /// Returns the device identifier.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the coefficient scalar.
    #[must_use]
    pub const fn scalar(self) -> Scalar {
        self.scalar
    }
}

/// A person's outer Lagrange coefficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OuterCoefficient {
    person: PersonId,
    slot: Slot,
    member: MemberPoint,
    scalar: Scalar,
}

impl OuterCoefficient {
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
    pub const fn member(self) -> MemberPoint {
        self.member
    }

    /// Returns the coefficient scalar.
    #[must_use]
    pub const fn scalar(self) -> Scalar {
        self.scalar
    }
}

/// A canonical accepted device support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerSupport {
    participants: Vec<DeviceParticipant>,
    coefficients: Vec<Scalar>,
}

impl InnerSupport {
    /// Creates a support sorted by device identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty support, duplicate device, or duplicate
    /// Shamir node.
    pub fn new(mut participants: Vec<DeviceParticipant>) -> Result<Self> {
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
    pub fn participants(&self) -> &[DeviceParticipant] {
        &self.participants
    }

    /// Returns one device's coefficient.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the device is absent.
    pub fn coefficient(&self, device: DeviceId) -> Result<InnerCoefficient> {
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
    pub fn participant(&self, device: DeviceId) -> Result<DeviceParticipant> {
        self.participants
            .binary_search_by_key(&device, |participant| participant.device)
            .map(|index| self.participants[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// A canonical accepted person support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterSupport {
    participants: Vec<PersonParticipant>,
    coefficients: Vec<Scalar>,
}

impl OuterSupport {
    /// Creates a support sorted by outer slot.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty support or duplicate person, slot, or
    /// Shamir node.
    pub fn new(mut participants: Vec<PersonParticipant>) -> Result<Self> {
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
    pub fn participants(&self) -> &[PersonParticipant] {
        &self.participants
    }

    /// Returns one person's coefficient.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the person is absent.
    pub fn coefficient(&self, person: PersonId) -> Result<OuterCoefficient> {
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
    pub fn participant(&self, slot: Slot) -> Result<PersonParticipant> {
        self.participants
            .binary_search_by_key(&slot, |participant| participant.slot)
            .map(|index| self.participants[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

fn reject_duplicate_devices(participants: &[DeviceParticipant]) -> Result<()> {
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

fn reject_duplicate_people(participants: &[PersonParticipant]) -> Result<()> {
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
