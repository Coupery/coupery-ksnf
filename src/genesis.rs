//! Validation for externally provisioned shares.

use core::fmt;

use crate::algebra::{Element, Point, SecretScalar};
use crate::keys::{IdentityKey, MemberPoint, SharePoint, VaultKey, anchor_share, signing_share};
use crate::shamir::Node;
use crate::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use crate::types::{DeviceId, PersonId, Slot, VaultId};
use crate::{Error, Result};

/// Public commitments to one Shamir polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPolynomial {
    constant: Point,
    commitments: Vec<Element>,
}

impl PublicPolynomial {
    /// Validates a nonempty coefficient-commitment vector.
    ///
    /// # Errors
    ///
    /// Returns an error when the vector is empty or its constant is identity.
    pub fn new(commitments: Vec<Element>) -> Result<Self> {
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

    /// Returns the coefficient commitments in constant-first order.
    #[must_use]
    pub fn commitments(&self) -> &[Element] {
        &self.commitments
    }

    /// Returns the nonidentity constant point.
    #[must_use]
    pub const fn constant(&self) -> Point {
        self.constant
    }

    /// Evaluates the commitment polynomial at `node`.
    #[must_use]
    pub fn evaluate(&self, node: Node) -> Element {
        self.commitments
            .iter()
            .rev()
            .fold(Element::IDENTITY, |value, coefficient| {
                value * node.scalar() + *coefficient
            })
    }

    /// Checks one public share.
    #[must_use]
    pub fn verifies(&self, node: Node, share: SharePoint) -> bool {
        self.evaluate(node) == share.element()
    }
}

/// One device's public genesis data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicDevice {
    device: DeviceId,
    node: Node,
    identity_share: SharePoint,
    member_share: SharePoint,
}

impl PublicDevice {
    /// Creates a public device entry.
    #[must_use]
    pub const fn new(
        device: DeviceId,
        node: Node,
        identity_share: SharePoint,
        member_share: SharePoint,
    ) -> Self {
        Self {
            device,
            node,
            identity_share,
            member_share,
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

    /// Returns the identity-share point.
    #[must_use]
    pub const fn identity_share(self) -> SharePoint {
        self.identity_share
    }

    /// Returns the member-share point.
    #[must_use]
    pub const fn member_share(self) -> SharePoint {
        self.member_share
    }
}

/// One person's validated public genesis data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPerson {
    person: PersonId,
    outer_node: Node,
    identity: PublicPolynomial,
    member: PublicPolynomial,
    devices: Vec<PublicDevice>,
}

impl PublicPerson {
    /// Validates one person's identity and member sharings.
    ///
    /// # Errors
    ///
    /// Returns an error for unequal thresholds, duplicate entries, too few
    /// devices, or an invalid public share.
    pub fn new(
        person: PersonId,
        outer_node: Node,
        identity: PublicPolynomial,
        member: PublicPolynomial,
        mut devices: Vec<PublicDevice>,
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

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(&self) -> PersonId {
        self.person
    }

    /// Returns the outer Shamir node.
    #[must_use]
    pub const fn outer_node(&self) -> Node {
        self.outer_node
    }

    /// Returns the stable identity key.
    #[must_use]
    pub const fn identity_key(&self) -> IdentityKey {
        IdentityKey::new(self.identity.constant())
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member_point(&self) -> MemberPoint {
        MemberPoint::new(self.member.constant())
    }

    /// Returns the inner threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.member.threshold()
    }

    /// Returns the sorted public device entries.
    #[must_use]
    pub fn devices(&self) -> &[PublicDevice] {
        &self.devices
    }

    fn device(&self, device: DeviceId) -> Result<PublicDevice> {
        self.devices
            .binary_search_by_key(&device, |entry| entry.device)
            .map(|index| self.devices[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// Validated public genesis data for one vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPublicGenesis {
    vault: VaultId,
    outer: PublicPolynomial,
    people: Vec<PublicPerson>,
}

impl ValidatedPublicGenesis {
    /// Validates outer and inner public genesis data.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate people or nodes, too few people, or an
    /// outer share that differs from its member point.
    pub fn from_parts(
        vault: VaultId,
        outer: PublicPolynomial,
        mut people: Vec<PublicPerson>,
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
    pub const fn vault_key(&self) -> VaultKey {
        VaultKey::new(self.outer.constant())
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
    pub fn person(&self, person: PersonId) -> Result<&PublicPerson> {
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
    pub fn outer_support(&self, people: &[PersonId]) -> Result<OuterSupport> {
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
    pub fn inner_support(&self, person: PersonId, devices: &[DeviceId]) -> Result<InnerSupport> {
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
        identity: SecretScalar,
        member: SecretScalar,
    ) -> Result<DeviceGenesis> {
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
            identity_key: public_person.identity_key(),
            member_point: public_person.member_point(),
            vault_key: self.vault_key(),
            identity,
            anchor,
        })
    }
}

/// One device's validated secret genesis state.
pub struct DeviceGenesis {
    vault: VaultId,
    person: PersonId,
    device: DeviceId,
    outer_node: Node,
    node: Node,
    identity_map: IdentityMap,
    identity_key: IdentityKey,
    member_point: MemberPoint,
    vault_key: VaultKey,
    identity: SecretScalar,
    anchor: SecretScalar,
}

impl DeviceGenesis {
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

    /// Returns the person's outer Shamir node.
    #[must_use]
    pub const fn outer_node(&self) -> Node {
        self.outer_node
    }

    /// Returns the Shamir node.
    #[must_use]
    pub const fn node(&self) -> Node {
        self.node
    }

    /// Returns the stable identity key.
    #[must_use]
    pub const fn identity_key(&self) -> IdentityKey {
        self.identity_key
    }

    /// Returns the vault-local member point.
    #[must_use]
    pub const fn member_point(&self) -> MemberPoint {
        self.member_point
    }

    /// Returns the stable vault key.
    #[must_use]
    pub const fn vault_key(&self) -> VaultKey {
        self.vault_key
    }

    /// Borrows the identity share for one operation.
    pub fn with_identity<T>(&self, use_share: impl FnOnce(&crate::algebra::Scalar) -> T) -> T {
        self.identity.expose(use_share)
    }

    /// Borrows the affine anchor share for one operation.
    pub fn with_anchor<T>(&self, use_share: impl FnOnce(&crate::algebra::Scalar) -> T) -> T {
        self.anchor.expose(use_share)
    }

    /// Recomputes the current member signing share.
    #[must_use]
    pub fn signing_share(&self) -> SecretScalar {
        signing_share(&self.identity, &self.anchor)
    }

    pub(crate) fn into_parts(self) -> DeviceGenesisParts {
        DeviceGenesisParts {
            vault: self.vault,
            person: self.person,
            device: self.device,
            outer_node: self.outer_node,
            node: self.node,
            identity_map: self.identity_map,
            identity_key: self.identity_key,
            member_point: self.member_point,
            vault_key: self.vault_key,
            identity: self.identity,
            anchor: self.anchor,
        }
    }
}

pub(crate) struct DeviceGenesisParts {
    pub(crate) vault: VaultId,
    pub(crate) person: PersonId,
    pub(crate) device: DeviceId,
    pub(crate) outer_node: Node,
    pub(crate) node: Node,
    pub(crate) identity_map: IdentityMap,
    pub(crate) identity_key: IdentityKey,
    pub(crate) member_point: MemberPoint,
    pub(crate) vault_key: VaultKey,
    pub(crate) identity: SecretScalar,
    pub(crate) anchor: SecretScalar,
}

#[derive(Eq, PartialEq)]
pub(crate) struct IdentityMap {
    pub(crate) commitments: Vec<Element>,
    pub(crate) devices: Vec<(DeviceId, Node, SharePoint)>,
}

impl fmt::Debug for DeviceGenesis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceGenesis")
            .field("vault", &self.vault)
            .field("person", &self.person)
            .field("device", &self.device)
            .field("outer_node", &self.outer_node)
            .field("node", &self.node)
            .field("identity_map", &"[REDACTED]")
            .field("identity_key", &self.identity_key)
            .field("member_point", &self.member_point)
            .field("vault_key", &self.vault_key)
            .field("identity", &"[REDACTED]")
            .field("anchor", &"[REDACTED]")
            .finish()
    }
}

fn secret_element(secret: &SecretScalar) -> Element {
    secret.expose(|scalar| Element::from_scalar(*scalar))
}
