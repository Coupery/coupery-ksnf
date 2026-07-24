use std::collections::BTreeSet;

use frost_core::{Field, Group};

use crate::algebra::{Element, Point};
use crate::encoding::{Decoder, Encoder};
use crate::keys::SharePoint;
use crate::profile::{DefaultProfile, Profile};
use crate::shamir::Node;
use crate::support::SourceWeight;
use crate::types::{ActivationHandle, CommandId, DeviceId, PersonId, ScopeId};
use crate::{Error, Result};

use super::count_u16;

type FieldOf<P> = <<P as Profile>::Group as Group>::Field;

/// One target device in a single sharing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetDevice<P: Profile = DefaultProfile> {
    device: DeviceId,
    node: Node<P>,
}

impl<P: Profile> TargetDevice<P> {
    /// Creates a target device.
    #[must_use]
    pub const fn new(device: DeviceId, node: Node<P>) -> Self {
        Self { device, node }
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
}

/// A target shape for one Shamir sharing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleShape<P: Profile = DefaultProfile> {
    threshold: u16,
    devices: Vec<TargetDevice<P>>,
}

impl<P: Profile> SingleShape<P> {
    /// Validates a single-sharing target shape.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold, too few devices, or duplicates.
    pub fn new(threshold: u16, mut devices: Vec<TargetDevice<P>>) -> Result<Self> {
        if threshold == 0 || usize::from(threshold) > devices.len() {
            return Err(Error::SupportMismatch);
        }
        devices.sort_unstable_by_key(|device| device.device);
        reject_device_duplicates(&devices)?;
        Ok(Self { threshold, devices })
    }

    /// Returns the threshold.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Returns the sorted target devices.
    #[must_use]
    pub fn devices(&self) -> &[TargetDevice<P>] {
        &self.devices
    }

    fn device(&self, device: DeviceId) -> Result<TargetDevice<P>> {
        self.devices
            .binary_search_by_key(&device, |entry| entry.device)
            .map(|index| self.devices[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// One person's target sharing in an outer redistribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterTarget<P: Profile = DefaultProfile> {
    person: PersonId,
    node: Node<P>,
    inner: SingleShape<P>,
}

impl<P: Profile> OuterTarget<P> {
    /// Creates one outer target.
    #[must_use]
    pub const fn new(person: PersonId, node: Node<P>, inner: SingleShape<P>) -> Self {
        Self {
            person,
            node,
            inner,
        }
    }

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(&self) -> PersonId {
        self.person
    }

    /// Returns the outer Shamir node.
    #[must_use]
    pub const fn node(&self) -> Node<P> {
        self.node
    }

    /// Returns the inner target shape.
    #[must_use]
    pub const fn inner(&self) -> &SingleShape<P> {
        &self.inner
    }
}

/// A composed outer and inner target shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterShape<P: Profile = DefaultProfile> {
    threshold: u16,
    people: Vec<OuterTarget<P>>,
}

impl<P: Profile> OuterShape<P> {
    /// Validates a composed target shape.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold, too few people, or duplicate
    /// people, nodes, or devices.
    pub fn new(threshold: u16, mut people: Vec<OuterTarget<P>>) -> Result<Self> {
        if threshold == 0 || usize::from(threshold) > people.len() {
            return Err(Error::SupportMismatch);
        }
        people.sort_unstable_by_key(|person| person.person);
        let mut devices = BTreeSet::new();
        for (index, person) in people.iter().enumerate() {
            if people[..index]
                .iter()
                .any(|prior| prior.person == person.person)
            {
                return Err(Error::DuplicateParticipant);
            }
            if people[..index]
                .iter()
                .any(|prior| prior.node == person.node)
            {
                return Err(Error::DuplicateNode);
            }
            for device in person.inner.devices() {
                if !devices.insert(device.device) {
                    return Err(Error::DuplicateParticipant);
                }
            }
        }
        Ok(Self { threshold, people })
    }

    /// Returns the outer threshold.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Returns the sorted person targets.
    #[must_use]
    pub fn people(&self) -> &[OuterTarget<P>] {
        &self.people
    }

    fn person(&self, person: PersonId) -> Result<&OuterTarget<P>> {
        self.people
            .binary_search_by_key(&person, |entry| entry.person)
            .map(|index| &self.people[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// A redistribution target shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetShape<P: Profile = DefaultProfile> {
    /// One Shamir sharing.
    Single(SingleShape<P>),
    /// An outer sharing linked to inner member sharings.
    Outer(OuterShape<P>),
}

impl<P: Profile> TargetShape<P> {
    /// Returns every target identifier in canonical order.
    #[must_use]
    pub fn targets(&self) -> Vec<TargetId> {
        match self {
            Self::Single(shape) => shape
                .devices
                .iter()
                .map(|device| TargetId::Single(device.device))
                .collect(),
            Self::Outer(shape) => shape
                .people
                .iter()
                .flat_map(|person| {
                    person.inner.devices.iter().map(|device| TargetId::Outer {
                        person: person.person,
                        device: device.device,
                    })
                })
                .collect(),
        }
    }

    pub(crate) fn target_node(&self, target: TargetId) -> Result<Node<P>> {
        match (self, target) {
            (Self::Single(shape), TargetId::Single(device)) => Ok(shape.device(device)?.node),
            (Self::Outer(shape), TargetId::Outer { person, device }) => {
                Ok(shape.person(person)?.inner.device(device)?.node)
            }
            _ => Err(Error::ParticipantMismatch),
        }
    }

    fn encode(&self, encoder: &mut Encoder<P>) -> Result<()> {
        match self {
            Self::Single(shape) => {
                encoder.put_u8(0);
                encode_single_shape(encoder, shape)?;
            }
            Self::Outer(shape) => {
                encoder.put_u8(1);
                encoder.put_u16(shape.threshold);
                encoder.put_u16(count_u16(shape.people.len())?);
                for person in &shape.people {
                    encoder.put_fixed(person.person.as_bytes());
                    encoder.put_scalar(&person.node.scalar());
                    encode_single_shape(encoder, &person.inner)?;
                }
            }
        }
        Ok(())
    }
}

/// One canonical redistribution target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetId {
    /// A device in a single sharing.
    Single(DeviceId),
    /// A device below one outer person.
    Outer {
        /// The outer person.
        person: PersonId,
        /// The target device.
        device: DeviceId,
    },
}

impl TargetId {
    /// Returns the target device.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        match self {
            Self::Single(device) | Self::Outer { device, .. } => device,
        }
    }

    pub(super) fn encode<P: Profile>(self, encoder: &mut Encoder<P>) {
        match self {
            Self::Single(device) => {
                encoder.put_u8(0);
                encoder.put_fixed(device.as_bytes());
            }
            Self::Outer { person, device } => {
                encoder.put_u8(1);
                encoder.put_fixed(person.as_bytes());
                encoder.put_fixed(device.as_bytes());
            }
        }
    }

    pub(super) fn decode<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<Self> {
        match decoder.get_u8()? {
            0 => Ok(Self::Single(DeviceId::new(decoder.get_fixed()?))),
            1 => Ok(Self::Outer {
                person: PersonId::new(decoder.get_fixed()?),
                device: DeviceId::new(decoder.get_fixed()?),
            }),
            _ => Err(Error::InvalidTranscript),
        }
    }
}

/// A mandatory redistribution role.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RoleId {
    /// A weighted source-share contribution.
    Source(DeviceId),
    /// A zero-constant target refresh contribution.
    Refresher(DeviceId),
}

impl RoleId {
    /// Returns the role's device.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        match self {
            Self::Source(device) | Self::Refresher(device) => device,
        }
    }

    pub(super) fn encode<P: Profile>(self, encoder: &mut Encoder<P>) {
        match self {
            Self::Source(device) => {
                encoder.put_u8(0);
                encoder.put_fixed(device.as_bytes());
            }
            Self::Refresher(device) => {
                encoder.put_u8(1);
                encoder.put_fixed(device.as_bytes());
            }
        }
    }

    pub(super) fn decode<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<Self> {
        match decoder.get_u8()? {
            0 => Ok(Self::Source(DeviceId::new(decoder.get_fixed()?))),
            1 => Ok(Self::Refresher(DeviceId::new(decoder.get_fixed()?))),
            _ => Err(Error::InvalidTranscript),
        }
    }

    pub(super) fn bytes<P: Profile>(self) -> Vec<u8> {
        let mut encoder = Encoder::<P>::for_profile();
        self.encode(&mut encoder);
        encoder.finish()
    }
}

/// One mandatory role and its required constant point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleSpec<P: Profile = DefaultProfile> {
    pub(super) role: RoleId,
    pub(super) constant: Element<P>,
    pub(super) source: Option<(SharePoint<P>, SourceWeight<P>)>,
}

impl<P: Profile> RoleSpec<P> {
    /// Creates a source role from a support-derived weight.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantMismatch`] when the device differs.
    pub fn source(device: DeviceId, share: SharePoint<P>, weight: SourceWeight<P>) -> Result<Self> {
        if device != weight.device() {
            return Err(Error::ParticipantMismatch);
        }
        Ok(Self {
            role: RoleId::Source(device),
            constant: share.element() * weight.scalar(),
            source: Some((share, weight)),
        })
    }

    /// Creates a zero-constant refresher role.
    #[must_use]
    pub fn refresher(device: DeviceId) -> Self {
        Self {
            role: RoleId::Refresher(device),
            constant: Element::identity(),
            source: None,
        }
    }

    /// Returns the role identifier.
    #[must_use]
    pub const fn role(self) -> RoleId {
        self.role
    }

    /// Returns the required constant point.
    #[must_use]
    pub const fn constant(self) -> Element<P> {
        self.constant
    }
}

/// Immutable parameters for one redistribution candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command<P: Profile = DefaultProfile> {
    pub(super) scope: ScopeId,
    pub(super) command: CommandId,
    pub(super) predecessor: ActivationHandle,
    pub(super) anchor: Point<P>,
    pub(super) shape: TargetShape<P>,
    pub(super) roles: Vec<RoleSpec<P>>,
}

impl<P: Profile> Command<P> {
    /// Validates one candidate command.
    ///
    /// # Errors
    ///
    /// Returns an error unless source constants sum to the anchor and every
    /// target device has one refresher role.
    pub fn new(
        scope: ScopeId,
        command: CommandId,
        predecessor: ActivationHandle,
        anchor: Point<P>,
        shape: TargetShape<P>,
        mut roles: Vec<RoleSpec<P>>,
    ) -> Result<Self> {
        roles.sort_unstable_by_key(|role| role.role);
        if roles.is_empty() {
            return Err(Error::EmptyInput);
        }
        for pair in roles.windows(2) {
            if pair[0].role == pair[1].role {
                return Err(Error::DuplicateParticipant);
            }
        }
        let source_sum = roles
            .iter()
            .filter(|role| matches!(role.role, RoleId::Source(_)))
            .fold(Element::identity(), |sum, role| sum + role.constant);
        if source_sum != Element::from(anchor) {
            return Err(Error::ShareMismatch);
        }
        let refreshers = roles
            .iter()
            .filter_map(|role| match role.role {
                RoleId::Refresher(device) => Some(device),
                RoleId::Source(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let targets = shape
            .targets()
            .into_iter()
            .map(TargetId::device)
            .collect::<BTreeSet<_>>();
        if refreshers != targets {
            return Err(Error::SupportMismatch);
        }
        Ok(Self {
            scope,
            command,
            predecessor,
            anchor,
            shape,
            roles,
        })
    }

    /// Returns canonical command bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for oversized collections.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encoder.put_fixed(self.scope.as_bytes());
        encoder.put_fixed(self.command.as_bytes());
        encoder.put_fixed(self.predecessor.as_bytes());
        encoder.put_point(self.anchor);
        self.shape.encode(&mut encoder)?;
        encoder.put_u16(count_u16(self.roles.len())?);
        for role in &self.roles {
            role.role.encode(&mut encoder);
            encoder.put_element(role.constant);
            if let Some((share, weight)) = role.source {
                encoder.put_element(share.element());
                encoder.put_scalar(&weight.scalar());
            } else {
                encoder.put_element(Element::identity());
                encoder.put_scalar(&FieldOf::<P>::zero());
            }
        }
        Ok(encoder.finish())
    }

    /// Checks canonical command bytes against locally derived parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandMismatch`] when the bytes differ.
    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<()> {
        if self.to_bytes()?.as_slice() == bytes {
            Ok(())
        } else {
            Err(Error::CommandMismatch)
        }
    }

    /// Returns the activation scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the command identifier.
    #[must_use]
    pub const fn id(&self) -> CommandId {
        self.command
    }

    /// Returns the predecessor handle.
    #[must_use]
    pub const fn predecessor(&self) -> ActivationHandle {
        self.predecessor
    }

    /// Returns the stable anchored point.
    #[must_use]
    pub const fn anchor(&self) -> Point<P> {
        self.anchor
    }

    /// Returns the target shape.
    #[must_use]
    pub const fn shape(&self) -> &TargetShape<P> {
        &self.shape
    }

    /// Returns the sorted mandatory roles.
    #[must_use]
    pub fn roles(&self) -> &[RoleSpec<P>] {
        &self.roles
    }

    pub(super) fn role(&self, role: RoleId) -> Result<&RoleSpec<P>> {
        self.roles
            .binary_search_by_key(&role, |entry| entry.role)
            .map(|index| &self.roles[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

fn encode_single_shape<P: Profile>(encoder: &mut Encoder<P>, shape: &SingleShape<P>) -> Result<()> {
    encoder.put_u16(shape.threshold);
    encoder.put_u16(count_u16(shape.devices.len())?);
    for device in &shape.devices {
        encoder.put_fixed(device.device.as_bytes());
        encoder.put_scalar(&device.node.scalar());
    }
    Ok(())
}

fn reject_device_duplicates<P: Profile>(devices: &[TargetDevice<P>]) -> Result<()> {
    for (index, device) in devices.iter().enumerate() {
        if devices[..index]
            .iter()
            .any(|prior| prior.device == device.device)
        {
            return Err(Error::DuplicateParticipant);
        }
        if devices[..index]
            .iter()
            .any(|prior| prior.node == device.node)
        {
            return Err(Error::DuplicateNode);
        }
    }
    Ok(())
}
