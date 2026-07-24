//! Import and validation for an existing sharing.
//!
//! This module neither runs nor proves a DKG.

use core::fmt;

use crate::algebra::{Element, Point, SecretScalar};
use crate::keys::{IdentityKey, MemberPoint, SharePoint, VaultKey, anchor_share};
use crate::profile::{DefaultProfile, Profile};
use crate::shamir::Node;
use crate::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use crate::types::{DeviceId, PersonId, Slot, VaultId};
use crate::{Error, Result};

/// Public commitments to one Shamir polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPolynomial<P: Profile = DefaultProfile> {
    constant: Point<P>,
    commitments: Vec<Element<P>>,
}

impl<P: Profile> PublicPolynomial<P> {
    /// Validates a nonempty coefficient-commitment vector.
    ///
    /// # Errors
    ///
    /// Returns an error when the vector is empty or its constant is identity.
    pub fn new(commitments: Vec<Element<P>>) -> Result<Self> {
        let constant = commitments.first().copied().ok_or(Error::EmptyInput)?;
        Ok(Self {
            constant: Point::try_from(constant)?,
            commitments,
        })
    }

    /// Returns the threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.commitments.len()
    }

    fn evaluate(&self, node: Node<P>) -> Element<P> {
        evaluate_commitments(&self.commitments, node)
    }

    fn verifies(&self, node: Node<P>, share: SharePoint<P>) -> bool {
        self.evaluate(node) == share.element()
    }
}

/// One device's public genesis data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicDevice<P: Profile = DefaultProfile> {
    device: DeviceId,
    node: Node<P>,
    identity_share: SharePoint<P>,
    member_share: SharePoint<P>,
}

impl<P: Profile> PublicDevice<P> {
    /// Creates a public device entry.
    #[must_use]
    pub const fn new(
        device: DeviceId,
        node: Node<P>,
        identity_share: SharePoint<P>,
        member_share: SharePoint<P>,
    ) -> Self {
        Self {
            device,
            node,
            identity_share,
            member_share,
        }
    }
}

/// One person's validated public genesis data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPerson<P: Profile = DefaultProfile> {
    person: PersonId,
    outer_node: Node<P>,
    identity: PublicPolynomial<P>,
    member: PublicPolynomial<P>,
    devices: Vec<PublicDevice<P>>,
}

impl<P: Profile> PublicPerson<P> {
    /// Validates one person's identity and member sharings.
    ///
    /// # Errors
    ///
    /// Returns an error for unequal thresholds, duplicate entries, too few
    /// devices, or an invalid public share.
    pub fn new(
        person: PersonId,
        outer_node: Node<P>,
        identity: PublicPolynomial<P>,
        member: PublicPolynomial<P>,
        mut devices: Vec<PublicDevice<P>>,
    ) -> Result<Self> {
        if identity.threshold() != member.threshold() {
            return Err(Error::LengthMismatch);
        }
        if devices.len() < identity.threshold() {
            return Err(Error::SupportMismatch);
        }
        devices.sort_unstable_by_key(|device| device.device);
        for pair in devices.windows(2) {
            if pair[0].device == pair[1].device {
                return Err(Error::DuplicateParticipant);
            }
        }
        for (index, device) in devices.iter().enumerate() {
            if devices[..index]
                .iter()
                .any(|prior| prior.node == device.node)
            {
                return Err(Error::DuplicateNode);
            }
            if !identity.verifies(device.node, device.identity_share)
                || !member.verifies(device.node, device.member_share)
            {
                return Err(Error::ShareMismatch);
            }
        }
        Ok(Self {
            person,
            outer_node,
            identity,
            member,
            devices,
        })
    }

    /// Returns the stable identity key.
    #[must_use]
    pub const fn identity_key(&self) -> IdentityKey<P> {
        IdentityKey::new(self.identity.constant)
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member_point(&self) -> MemberPoint<P> {
        MemberPoint::new(self.member.constant)
    }

    fn threshold(&self) -> usize {
        self.member.threshold()
    }

    fn device(&self, device: DeviceId) -> Result<PublicDevice<P>> {
        self.devices
            .binary_search_by_key(&device, |entry| entry.device)
            .map(|index| self.devices[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// Validated public genesis data for one vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPublicGenesis<P: Profile = DefaultProfile> {
    vault: VaultId,
    outer: PublicPolynomial<P>,
    people: Vec<PublicPerson<P>>,
}

impl<P: Profile> ValidatedPublicGenesis<P> {
    /// Validates outer and inner public genesis data.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate people or nodes, too few people, or an
    /// outer share that differs from its member point.
    pub fn validate(
        vault: VaultId,
        outer: PublicPolynomial<P>,
        mut people: Vec<PublicPerson<P>>,
    ) -> Result<Self> {
        if people.len() < outer.threshold() {
            return Err(Error::SupportMismatch);
        }
        people.sort_unstable_by_key(|person| person.person);
        for pair in people.windows(2) {
            if pair[0].person == pair[1].person {
                return Err(Error::DuplicateParticipant);
            }
        }
        for (index, person) in people.iter().enumerate() {
            if people[..index]
                .iter()
                .any(|prior| prior.outer_node == person.outer_node)
            {
                return Err(Error::DuplicateNode);
            }
            if outer.evaluate(person.outer_node) != Element::from(person.member_point().point()) {
                return Err(Error::ShareMismatch);
            }
        }
        Ok(Self {
            vault,
            outer,
            people,
        })
    }

    /// Returns the vault identifier.
    #[must_use]
    pub const fn vault(&self) -> VaultId {
        self.vault
    }

    /// Returns the stable vault key.
    #[must_use]
    pub const fn vault_key(&self) -> VaultKey<P> {
        VaultKey::new(self.outer.constant)
    }

    /// Returns the outer threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.outer.threshold()
    }

    /// Returns one person's public data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the person is absent.
    pub fn person(&self, person: PersonId) -> Result<&PublicPerson<P>> {
        self.people
            .binary_search_by_key(&person, |entry| entry.person)
            .map(|index| &self.people[index])
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Builds an exact outer-threshold support.
    ///
    /// Slots follow sorted person order and start at one.
    ///
    /// # Errors
    ///
    /// Returns an error unless `people` names one exact threshold support.
    pub fn outer_support(&self, people: &[PersonId]) -> Result<OuterSupport<P>> {
        if people.len() != self.threshold() {
            return Err(Error::SupportMismatch);
        }
        let mut selected = people.to_vec();
        selected.sort_unstable();
        if selected.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::DuplicateParticipant);
        }
        let mut participants = Vec::with_capacity(selected.len());
        for (index, person_id) in selected.into_iter().enumerate() {
            let person = self.person(person_id)?;
            let slot = u16::try_from(index + 1).map_err(|_| Error::LengthOverflow)?;
            participants.push(PersonParticipant::new(
                person_id,
                Slot::new(slot),
                person.outer_node,
                person.member_point(),
            ));
        }
        OuterSupport::new(participants)
    }

    /// Builds one person's exact inner-threshold support.
    ///
    /// # Errors
    ///
    /// Returns an error unless `devices` names one exact threshold support.
    pub fn inner_support(&self, person: PersonId, devices: &[DeviceId]) -> Result<InnerSupport<P>> {
        let person = self.person(person)?;
        if devices.len() != person.threshold() {
            return Err(Error::SupportMismatch);
        }
        let participants = devices
            .iter()
            .map(|device_id| {
                let device = person.device(*device_id)?;
                Ok(DeviceParticipant::new(
                    *device_id,
                    device.node,
                    device.member_share,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        InnerSupport::new(participants)
    }

    /// Attaches one device's secret shares to validated public data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ShareMismatch`] when either secret is invalid.
    pub fn attach_share(
        &self,
        person: PersonId,
        device: DeviceId,
        identity: SecretScalar<P>,
        member: SecretScalar<P>,
    ) -> Result<DeviceGenesis<P>> {
        let public = self.person(person)?.device(device)?;
        if secret_element(&identity) != public.identity_share.element()
            || secret_element(&member) != public.member_share.element()
        {
            return Err(Error::ShareMismatch);
        }
        let anchor = anchor_share(&member, &identity);
        drop(member);
        let public_person = self.person(person)?;
        Ok(DeviceGenesis {
            vault: self.vault,
            person,
            device,
            outer_node: public_person.outer_node,
            node: public.node,
            identity_map: IdentityMap {
                commitments: public_person.identity.commitments.clone(),
                devices: public_person
                    .devices
                    .iter()
                    .map(|device| (device.device, device.node, device.identity_share))
                    .collect(),
            },
            member_map: MemberMap {
                commitments: public_person.member.commitments.clone(),
            },
            outer_map: OuterMap {
                commitments: self.outer.commitments.clone(),
                people: self
                    .people
                    .iter()
                    .map(|person| (person.person, person.outer_node, person.member_point()))
                    .collect(),
            },
            identity_key: public_person.identity_key(),
            member_point: public_person.member_point(),
            vault_key: self.vault_key(),
            identity,
            anchor,
        })
    }
}

/// One device's validated secret genesis state.
pub struct DeviceGenesis<P: Profile = DefaultProfile> {
    vault: VaultId,
    person: PersonId,
    device: DeviceId,
    outer_node: Node<P>,
    node: Node<P>,
    identity_map: IdentityMap<P>,
    member_map: MemberMap<P>,
    outer_map: OuterMap<P>,
    identity_key: IdentityKey<P>,
    member_point: MemberPoint<P>,
    vault_key: VaultKey<P>,
    identity: SecretScalar<P>,
    anchor: SecretScalar<P>,
}

impl<P: Profile> DeviceGenesis<P> {
    /// Returns the vault identifier.
    #[must_use]
    pub const fn vault(&self) -> VaultId {
        self.vault
    }

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(&self) -> PersonId {
        self.person
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// Returns the stable identity key.
    #[must_use]
    pub const fn identity_key(&self) -> IdentityKey<P> {
        self.identity_key
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member_point(&self) -> MemberPoint<P> {
        self.member_point
    }

    /// Returns the stable vault key.
    #[must_use]
    pub const fn vault_key(&self) -> VaultKey<P> {
        self.vault_key
    }

    pub(crate) fn into_parts(self) -> DeviceGenesisParts<P> {
        DeviceGenesisParts {
            vault: self.vault,
            person: self.person,
            device: self.device,
            outer_node: self.outer_node,
            node: self.node,
            identity_map: self.identity_map,
            member_map: self.member_map,
            outer_map: self.outer_map,
            identity_key: self.identity_key,
            member_point: self.member_point,
            vault_key: self.vault_key,
            identity: self.identity,
            anchor: self.anchor,
        }
    }
}

pub(crate) struct DeviceGenesisParts<P: Profile = DefaultProfile> {
    pub(crate) vault: VaultId,
    pub(crate) person: PersonId,
    pub(crate) device: DeviceId,
    pub(crate) outer_node: Node<P>,
    pub(crate) node: Node<P>,
    pub(crate) identity_map: IdentityMap<P>,
    pub(crate) member_map: MemberMap<P>,
    pub(crate) outer_map: OuterMap<P>,
    pub(crate) identity_key: IdentityKey<P>,
    pub(crate) member_point: MemberPoint<P>,
    pub(crate) vault_key: VaultKey<P>,
    pub(crate) identity: SecretScalar<P>,
    pub(crate) anchor: SecretScalar<P>,
}

#[derive(Eq, PartialEq)]
pub(crate) struct IdentityMap<P: Profile = DefaultProfile> {
    pub(crate) commitments: Vec<Element<P>>,
    pub(crate) devices: Vec<(DeviceId, Node<P>, SharePoint<P>)>,
}

#[derive(Eq, PartialEq)]
pub(crate) struct MemberMap<P: Profile = DefaultProfile> {
    pub(crate) commitments: Vec<Element<P>>,
}

#[derive(Eq, PartialEq)]
pub(crate) struct OuterMap<P: Profile = DefaultProfile> {
    pub(crate) commitments: Vec<Element<P>>,
    pub(crate) people: Vec<(PersonId, Node<P>, MemberPoint<P>)>,
}

impl<P: Profile> fmt::Debug for DeviceGenesis<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceGenesis")
            .field("vault", &self.vault)
            .field("person", &self.person)
            .field("device", &self.device)
            .field("outer_node", &self.outer_node)
            .field("node", &self.node)
            .field("identity_map", &"[REDACTED]")
            .field("member_map", &"[REDACTED]")
            .field("outer_map", &"[REDACTED]")
            .field("identity_key", &self.identity_key)
            .field("member_point", &self.member_point)
            .field("vault_key", &self.vault_key)
            .field("identity", &"[REDACTED]")
            .field("anchor", &"[REDACTED]")
            .finish()
    }
}

fn secret_element<P: Profile>(secret: &SecretScalar<P>) -> Element<P> {
    secret.expose(|scalar| Element::from_scalar(*scalar))
}

pub(crate) fn evaluate_commitments<P: Profile>(
    commitments: &[Element<P>],
    node: Node<P>,
) -> Element<P> {
    commitments
        .iter()
        .rev()
        .fold(Element::identity(), |value, coefficient| {
            value * node.scalar() + *coefficient
        })
}
