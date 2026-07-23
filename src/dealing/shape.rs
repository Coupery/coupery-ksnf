use std::collections::BTreeSet;

use crate::algebra::{Element, Point, Scalar};
use crate::encoding::{Decoder, Encoder};
use crate::keys::SharePoint;
use crate::shamir::Node;
use crate::support::SourceWeight;
use crate::types::{ActivationHandle, CommandId, DeviceId, PersonId, ScopeId};
use crate::{Error, Result};

use super::{VERSION, count_u16};

/// One target device in a single sharing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetDevice {
    device: DeviceId,
    node: Node,
}

impl TargetDevice {
    /// Creates a target device.
    #[must_use]
    pub const fn new(device: DeviceId, node: Node) -> Self {
        Self { device, node }
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
}

/// A target shape for one Shamir sharing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleShape {
    threshold: u16,
    devices: Vec<TargetDevice>,
}

impl SingleShape {
    /// Validates a single-sharing target shape.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold, too few devices, or duplicates.
    pub fn new(threshold: u16, mut devices: Vec<TargetDevice>) -> Result<Self> {
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
    pub fn devices(&self) -> &[TargetDevice] {
        &self.devices
    }

    fn device(&self, device: DeviceId) -> Result<TargetDevice> {
        self.devices
            .binary_search_by_key(&device, |entry| entry.device)
            .map(|index| self.devices[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// One person's target sharing in an outer redistribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterTarget {
    person: PersonId,
    node: Node,
    inner: SingleShape,
}

impl OuterTarget {
    /// Creates one outer target.
    #[must_use]
    pub const fn new(person: PersonId, node: Node, inner: SingleShape) -> Self {
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
    pub const fn node(&self) -> Node {
        self.node
    }

    /// Returns the inner target shape.
    #[must_use]
    pub const fn inner(&self) -> &SingleShape {
        &self.inner
    }
}

/// A composed outer and inner target shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterShape {
    threshold: u16,
    people: Vec<OuterTarget>,
}

impl OuterShape {
    /// Validates a composed target shape.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold, too few people, or duplicate
    /// people, nodes, or devices.
    pub fn new(threshold: u16, mut people: Vec<OuterTarget>) -> Result<Self> {
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
    pub fn people(&self) -> &[OuterTarget] {
        &self.people
    }

    fn person(&self, person: PersonId) -> Result<&OuterTarget> {
        self.people
            .binary_search_by_key(&person, |entry| entry.person)
            .map(|index| &self.people[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// A redistribution target shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetShape {
    /// One Shamir sharing.
    Single(SingleShape),
    /// An outer sharing linked to inner member sharings.
    Outer(OuterShape),
}

impl TargetShape {
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

    pub(crate) fn target_node(&self, target: TargetId) -> Result<Node> {
        match (self, target) {
            (Self::Single(shape), TargetId::Single(device)) => Ok(shape.device(device)?.node),
            (Self::Outer(shape), TargetId::Outer { person, device }) => {
                Ok(shape.person(person)?.inner.device(device)?.node)
            }
            _ => Err(Error::ParticipantMismatch),
        }
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<()> {
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

    pub(super) fn encode(self, encoder: &mut Encoder) {
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

    pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
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

    pub(super) fn encode(self, encoder: &mut Encoder) {
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

    pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        match decoder.get_u8()? {
            0 => Ok(Self::Source(DeviceId::new(decoder.get_fixed()?))),
            1 => Ok(Self::Refresher(DeviceId::new(decoder.get_fixed()?))),
            _ => Err(Error::InvalidTranscript),
        }
    }

    pub(super) fn bytes(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder);
        encoder.finish()
    }
}

/// One mandatory role and its required constant point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleSpec {
    pub(super) role: RoleId,
    pub(super) constant: Element,
    pub(super) source: Option<(SharePoint, SourceWeight)>,
}

impl RoleSpec {
    /// Creates a source role from a support-derived weight.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantMismatch`] when the device differs.
    pub fn source(device: DeviceId, share: SharePoint, weight: SourceWeight) -> Result<Self> {
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
    pub const fn refresher(device: DeviceId) -> Self {
        Self {
            role: RoleId::Refresher(device),
            constant: Element::IDENTITY,
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
    pub const fn constant(self) -> Element {
        self.constant
    }
}

/// Immutable parameters for one redistribution candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command {
    pub(super) scope: ScopeId,
    pub(super) command: CommandId,
    pub(super) predecessor: ActivationHandle,
    pub(super) anchor: Point,
    pub(super) shape: TargetShape,
    pub(super) roles: Vec<RoleSpec>,
}

impl Command {
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
        anchor: Point,
        shape: TargetShape,
        mut roles: Vec<RoleSpec>,
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
            .fold(Element::IDENTITY, |sum, role| sum + role.constant);
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
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
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
                encoder.put_element(Element::IDENTITY);
                encoder.put_scalar(&Scalar::ZERO);
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
    pub const fn anchor(&self) -> Point {
        self.anchor
    }

    /// Returns the target shape.
    #[must_use]
    pub const fn shape(&self) -> &TargetShape {
        &self.shape
    }

    /// Returns the sorted mandatory roles.
    #[must_use]
    pub fn roles(&self) -> &[RoleSpec] {
        &self.roles
    }

    pub(super) fn role(&self, role: RoleId) -> Result<&RoleSpec> {
        self.roles
            .binary_search_by_key(&role, |entry| entry.role)
            .map(|index| &self.roles[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

fn encode_single_shape(encoder: &mut Encoder, shape: &SingleShape) -> Result<()> {
    encoder.put_u16(shape.threshold);
    encoder.put_u16(count_u16(shape.devices.len())?);
    for device in &shape.devices {
        encoder.put_fixed(device.device.as_bytes());
        encoder.put_scalar(&device.node.scalar());
    }
    Ok(())
}

fn reject_device_duplicates(devices: &[TargetDevice]) -> Result<()> {
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
