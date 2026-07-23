//! Commit-before-open same-key redistribution.

use std::collections::{BTreeMap, BTreeSet};

use k256::elliptic_curve::Field as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algebra::{Element, Point, Scalar, SecretScalar};
use crate::encoding::Encoder;
use crate::hash::{self, Domain};
use crate::keys::SharePoint;
use crate::log_act::{LogAct, LogPhase, Terminal};
use crate::shamir::{Node, Polynomial};
use crate::support::SourceWeight;
use crate::types::{ActivationHandle, CommandId, DeviceId, PersonId, ScopeId};
use crate::{Error, Result};

const VERSION: u8 = 1;

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

    fn target_node(&self, target: TargetId) -> Result<Node> {
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

    fn encode(self, encoder: &mut Encoder) {
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

    fn encode(self, encoder: &mut Encoder) {
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

    fn bytes(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder);
        encoder.finish()
    }
}

/// One mandatory role and its required constant point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleSpec {
    role: RoleId,
    constant: Element,
    source: Option<(SharePoint, SourceWeight)>,
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
    scope: ScopeId,
    command: CommandId,
    predecessor: ActivationHandle,
    anchor: Point,
    shape: TargetShape,
    roles: Vec<RoleSpec>,
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

    fn role(&self, role: RoleId) -> Result<&RoleSpec> {
        self.roles
            .binary_search_by_key(&role, |entry| entry.role)
            .map(|index| &self.roles[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// Public coefficient points for one contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContributionPoints {
    /// One polynomial.
    Single(Vec<Element>),
    /// One outer polynomial and linked inner polynomials.
    Outer {
        /// Outer coefficient points.
        outer: Vec<Element>,
        /// Inner coefficient points sorted by person.
        members: Vec<(PersonId, Vec<Element>)>,
    },
}

impl ContributionPoints {
    /// Returns the anchored constant element.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyInput`] when a received point vector is empty.
    pub fn constant(&self) -> Result<Element> {
        match self {
            Self::Single(points) | Self::Outer { outer: points, .. } => {
                points.first().copied().ok_or(Error::EmptyInput)
            }
        }
    }

    /// Returns one linked inner polynomial's constant element.
    ///
    /// # Errors
    ///
    /// Returns an error when the points are not outer points or the person is
    /// absent.
    pub fn member_constant(&self, person: PersonId) -> Result<Element> {
        let Self::Outer { members, .. } = self else {
            return Err(Error::SupportMismatch);
        };
        let (_, points) = members
            .binary_search_by_key(&person, |(entry, _)| *entry)
            .map(|index| &members[index])
            .map_err(|_| Error::ParticipantNotFound)?;
        points.first().copied().ok_or(Error::EmptyInput)
    }

    /// Validates degree, constant, and outer linkage checks.
    ///
    /// # Errors
    ///
    /// Returns an error when the points differ from the command shape or
    /// required constant.
    pub fn validate(&self, shape: &TargetShape, constant: Element) -> Result<()> {
        match (self, shape) {
            (Self::Single(points), TargetShape::Single(target)) => {
                if points.len() != usize::from(target.threshold)
                    || points.first().copied() != Some(constant)
                {
                    return Err(Error::SupportMismatch);
                }
            }
            (Self::Outer { outer, members }, TargetShape::Outer(target)) => {
                if outer.len() != usize::from(target.threshold)
                    || outer.first().copied() != Some(constant)
                    || members.len() != target.people.len()
                {
                    return Err(Error::SupportMismatch);
                }
                for ((person, points), target_person) in members.iter().zip(&target.people) {
                    if *person != target_person.person
                        || points.len() != usize::from(target_person.inner.threshold)
                        || points.first().copied()
                            != Some(evaluate_points(outer, target_person.node))
                    {
                        return Err(Error::SupportMismatch);
                    }
                }
            }
            _ => return Err(Error::SupportMismatch),
        }
        Ok(())
    }

    /// Returns canonical point bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for oversized collections.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        match self {
            Self::Single(points) => {
                encoder.put_u8(0);
                encode_points(&mut encoder, points)?;
            }
            Self::Outer { outer, members } => {
                encoder.put_u8(1);
                encode_points(&mut encoder, outer)?;
                encoder.put_u16(count_u16(members.len())?);
                for (person, points) in members {
                    encoder.put_fixed(person.as_bytes());
                    encode_points(&mut encoder, points)?;
                }
            }
        }
        Ok(encoder.finish())
    }

    fn evaluate(&self, shape: &TargetShape, target: TargetId) -> Result<Element> {
        let node = shape.target_node(target)?;
        match (self, target) {
            (Self::Single(points), TargetId::Single(_)) => Ok(evaluate_points(points, node)),
            (Self::Outer { members, .. }, TargetId::Outer { person, .. }) => {
                let (_, points) = members
                    .binary_search_by_key(&person, |(entry, _)| *entry)
                    .map(|index| &members[index])
                    .map_err(|_| Error::ParticipantNotFound)?;
                Ok(evaluate_points(points, node))
            }
            _ => Err(Error::ParticipantMismatch),
        }
    }

    fn add_assign(&mut self, other: &Self) -> Result<()> {
        match (self, other) {
            (Self::Single(left), Self::Single(right)) => add_points(left, right),
            (
                Self::Outer {
                    outer: left_outer,
                    members: left_members,
                },
                Self::Outer {
                    outer: right_outer,
                    members: right_members,
                },
            ) => {
                add_points(left_outer, right_outer)?;
                if left_members.len() != right_members.len() {
                    return Err(Error::LengthMismatch);
                }
                for ((left_person, left), (right_person, right)) in
                    left_members.iter_mut().zip(right_members)
                {
                    if left_person != right_person {
                        return Err(Error::ParticipantMismatch);
                    }
                    add_points(left, right)?;
                }
                Ok(())
            }
            _ => Err(Error::SupportMismatch),
        }
    }
}

/// An opened contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opening {
    role: RoleId,
    points: ContributionPoints,
    salt: Scalar,
}

impl Opening {
    /// Creates a received opening for validation.
    #[must_use]
    pub const fn new(role: RoleId, points: ContributionPoints, salt: Scalar) -> Self {
        Self { role, points, salt }
    }

    /// Returns the role identifier.
    #[must_use]
    pub const fn role(&self) -> RoleId {
        self.role
    }

    /// Returns the public coefficient points.
    #[must_use]
    pub const fn points(&self) -> &ContributionPoints {
        &self.points
    }

    /// Returns the public commitment salt.
    #[must_use]
    pub const fn salt(&self) -> Scalar {
        self.salt
    }

    /// Returns canonical opening bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for oversized point vectors.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        self.role.encode(&mut encoder);
        encoder.put_bytes(&self.points.to_bytes()?)?;
        encoder.put_scalar(&self.salt);
        Ok(encoder.finish())
    }

    fn commitment(&self, command: &Command) -> Result<Scalar> {
        contribution_commitment(command, self.role, &self.points, self.salt)
    }
}

/// One private scalar delivery to a target.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateShare {
    #[zeroize(skip)]
    command: CommandId,
    #[zeroize(skip)]
    role: RoleId,
    #[zeroize(skip)]
    target: TargetId,
    value: Scalar,
}

impl PrivateShare {
    /// Creates a private delivery after channel authentication.
    #[must_use]
    pub fn new(command: CommandId, role: RoleId, target: TargetId, value: SecretScalar) -> Self {
        let scalar = value.expose(|scalar| *scalar);
        drop(value);
        Self {
            command,
            role,
            target,
            value: scalar,
        }
    }

    /// Returns the command identifier.
    #[must_use]
    pub const fn command(&self) -> CommandId {
        self.command
    }

    /// Returns the contributor role.
    #[must_use]
    pub const fn role(&self) -> RoleId {
        self.role
    }

    /// Returns the target.
    #[must_use]
    pub const fn target(&self) -> TargetId {
        self.target
    }

    /// Borrows the scalar for one operation.
    pub fn expose<T>(&self, use_share: impl FnOnce(&Scalar) -> T) -> T {
        use_share(&self.value)
    }
}

impl core::fmt::Debug for PrivateShare {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PrivateShare")
            .field("command", &self.command)
            .field("role", &self.role)
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// One unopened local contribution.
pub struct Contribution {
    command: CommandId,
    role: RoleId,
    block: SecretBlock,
    points: ContributionPoints,
    salt: SecretScalar,
    commitment: Scalar,
}

impl Contribution {
    /// Samples a weighted source contribution.
    ///
    /// # Errors
    ///
    /// Returns an error when the source share differs from the command or
    /// contribution sampling fails.
    pub fn source(
        command: &Command,
        device: DeviceId,
        source_share: &SecretScalar,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<Self> {
        let spec = command.role(RoleId::Source(device))?;
        let (share_point, weight) = spec.source.ok_or(Error::ParticipantMismatch)?;
        let point = source_share.expose(|value| Element::from_scalar(*value));
        if point != share_point.element() {
            return Err(Error::ShareMismatch);
        }
        let constant = source_share.expose(|value| SecretScalar::new(*value * weight.scalar()));
        Self::sample(command, spec, &constant, rng)
    }

    /// Samples a zero-constant refresher contribution.
    ///
    /// # Errors
    ///
    /// Returns an error when the role is absent or sampling fails.
    pub fn refresher(
        command: &Command,
        device: DeviceId,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<Self> {
        let spec = command.role(RoleId::Refresher(device))?;
        Self::sample(command, spec, &SecretScalar::new(Scalar::ZERO), rng)
    }

    /// Returns the role identifier.
    #[must_use]
    pub const fn role(&self) -> RoleId {
        self.role
    }

    /// Returns the commitment scalar.
    #[must_use]
    pub const fn commitment(&self) -> Scalar {
        self.commitment
    }

    /// Opens the public coefficient points and salt.
    #[must_use]
    pub fn opening(&self) -> Opening {
        Opening {
            role: self.role,
            points: self.points.clone(),
            salt: self.salt.expose(|value| *value),
        }
    }

    /// Creates one authenticated private delivery payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is absent.
    pub fn share(&self, command: &Command, target: TargetId) -> Result<PrivateShare> {
        if self.command != command.command {
            return Err(Error::CommandMismatch);
        }
        Ok(PrivateShare {
            command: self.command,
            role: self.role,
            target,
            value: self.block.evaluate(command.shape(), target)?,
        })
    }

    fn sample(
        command: &Command,
        spec: &RoleSpec,
        constant: &SecretScalar,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<Self> {
        if Element::from_scalar(constant.expose(|value| *value)) != spec.constant {
            return Err(Error::ShareMismatch);
        }
        let block = SecretBlock::sample(command.shape(), constant, rng)?;
        let points = block.points();
        points.validate(command.shape(), spec.constant)?;
        let salt = SecretScalar::new(Scalar::random(&mut *rng));
        let commitment =
            salt.expose(|salt| contribution_commitment(command, spec.role, &points, *salt))?;
        Ok(Self {
            command: command.command,
            role: spec.role,
            block,
            points,
            salt,
            commitment,
        })
    }
}

enum SecretBlock {
    Single(Polynomial),
    Outer {
        outer: Polynomial,
        members: Vec<(PersonId, Polynomial)>,
    },
}

impl SecretBlock {
    fn sample(
        shape: &TargetShape,
        constant: &SecretScalar,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<Self> {
        match shape {
            TargetShape::Single(target) => Ok(Self::Single(Polynomial::sample(
                usize::from(target.threshold),
                constant,
                rng,
            )?)),
            TargetShape::Outer(target) => {
                let outer = Polynomial::sample(usize::from(target.threshold), constant, rng)?;
                let mut members = Vec::with_capacity(target.people.len());
                for person in &target.people {
                    let member_constant = outer.evaluate(person.node);
                    members.push((
                        person.person,
                        Polynomial::sample(
                            usize::from(person.inner.threshold),
                            &member_constant,
                            rng,
                        )?,
                    ));
                }
                Ok(Self::Outer { outer, members })
            }
        }
    }

    fn points(&self) -> ContributionPoints {
        match self {
            Self::Single(polynomial) => ContributionPoints::Single(polynomial.commitments()),
            Self::Outer { outer, members } => ContributionPoints::Outer {
                outer: outer.commitments(),
                members: members
                    .iter()
                    .map(|(person, polynomial)| (*person, polynomial.commitments()))
                    .collect(),
            },
        }
    }

    fn evaluate(&self, shape: &TargetShape, target: TargetId) -> Result<Scalar> {
        let node = shape.target_node(target)?;
        match (self, target) {
            (Self::Single(polynomial), TargetId::Single(_)) => {
                Ok(polynomial.evaluate(node).expose(|value| *value))
            }
            (Self::Outer { members, .. }, TargetId::Outer { person, .. }) => {
                let (_, polynomial) = members
                    .binary_search_by_key(&person, |(entry, _)| *entry)
                    .map(|index| &members[index])
                    .map_err(|_| Error::ParticipantNotFound)?;
                Ok(polynomial.evaluate(node).expose(|value| *value))
            }
            _ => Err(Error::ParticipantMismatch),
        }
    }
}

/// A complete public opening transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateView {
    command: Command,
    commitments: Vec<(RoleId, Scalar)>,
    openings: Vec<Opening>,
    bytes: Vec<u8>,
    aggregate: ContributionPoints,
}

impl CandidateView {
    /// Returns the command.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// Returns exact common-view bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the summed public coefficient points.
    #[must_use]
    pub const fn aggregate(&self) -> &ContributionPoints {
        &self.aggregate
    }

    /// Returns one role's opening.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the role is absent.
    pub fn opening(&self, role: RoleId) -> Result<&Opening> {
        self.openings
            .binary_search_by_key(&role, |opening| opening.role)
            .map(|index| &self.openings[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// One target's authenticated receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetReceipt {
    command: CommandId,
    target: TargetId,
    view: Vec<u8>,
}

impl TargetReceipt {
    /// Creates a receipt after target authentication.
    #[must_use]
    pub const fn new(command: CommandId, target: TargetId, view: Vec<u8>) -> Self {
        Self {
            command,
            target,
            view,
        }
    }

    /// Returns the command identifier.
    #[must_use]
    pub const fn command(&self) -> CommandId {
        self.command
    }

    /// Returns the target.
    #[must_use]
    pub const fn target(&self) -> TargetId {
        self.target
    }

    /// Returns canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized view.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encoder.put_u8(VERSION);
        encoder.put_fixed(self.command.as_bytes());
        self.target.encode(&mut encoder);
        encoder.put_bytes(&self.view)?;
        Ok(encoder.finish())
    }
}

/// One target's unactivated share.
pub struct PendingShare {
    target: TargetId,
    share: SecretScalar,
    public: Element,
    points: ContributionPoints,
}

impl PendingShare {
    /// Returns the target.
    #[must_use]
    pub const fn target(&self) -> TargetId {
        self.target
    }

    /// Resolves the pending share under the terminal decision.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ShareMismatch`] if the aggregate share point differs.
    pub fn resolve(self, terminal: Terminal) -> Result<Option<InstalledShare>> {
        match terminal {
            Terminal::Aborted => Ok(None),
            Terminal::Activated(handle) => {
                if Element::from_scalar(self.share.expose(|value| *value)) != self.public {
                    return Err(Error::ShareMismatch);
                }
                Ok(Some(InstalledShare {
                    target: self.target,
                    handle,
                    share: self.share,
                    public: self.public,
                    points: self.points,
                }))
            }
        }
    }
}

/// One installed target share.
pub struct InstalledShare {
    target: TargetId,
    handle: ActivationHandle,
    share: SecretScalar,
    public: Element,
    points: ContributionPoints,
}

impl InstalledShare {
    /// Returns the target.
    #[must_use]
    pub const fn target(&self) -> TargetId {
        self.target
    }

    /// Returns the exact activation handle.
    #[must_use]
    pub const fn handle(&self) -> ActivationHandle {
        self.handle
    }

    /// Returns the public share element.
    #[must_use]
    pub const fn public(&self) -> Element {
        self.public
    }

    /// Returns the installed block's public coefficient points.
    #[must_use]
    pub const fn points(&self) -> &ContributionPoints {
        &self.points
    }

    /// Borrows the scalar for one operation.
    pub fn expose<T>(&self, use_share: impl FnOnce(&Scalar) -> T) -> T {
        self.share.expose(use_share)
    }

    pub(crate) fn into_share(self) -> SecretScalar {
        self.share
    }
}

impl core::fmt::Debug for InstalledShare {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InstalledShare")
            .field("target", &self.target)
            .field("handle", &self.handle)
            .field("share", &"[REDACTED]")
            .field("public", &self.public)
            .field("points", &self.points)
            .finish()
    }
}

/// One target's receipt and pending share.
pub struct TargetReady {
    receipt: TargetReceipt,
    pending: PendingShare,
}

impl TargetReady {
    /// Splits the public receipt from the private pending share.
    #[must_use]
    pub fn into_parts(self) -> (TargetReceipt, PendingShare) {
        (self.receipt, self.pending)
    }
}

/// A target-local private-share accumulator.
pub struct TargetAccumulator {
    view: CandidateView,
    target: TargetId,
    shares: BTreeMap<RoleId, SecretScalar>,
}

impl TargetAccumulator {
    /// Starts a target-local accumulator for one complete public view.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the target is absent.
    pub fn new(view: CandidateView, target: TargetId) -> Result<Self> {
        view.command.shape.target_node(target)?;
        Ok(Self {
            view,
            target,
            shares: BTreeMap::new(),
        })
    }

    /// Accepts one authenticated private share.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed tag, invalid evaluation, or altered
    /// replay.
    pub fn receive(&mut self, share: PrivateShare) -> Result<()> {
        if share.command != self.view.command.command || share.target != self.target {
            return Err(Error::InvalidTranscript);
        }
        let opening = self.view.opening(share.role)?;
        let expected = opening
            .points
            .evaluate(&self.view.command.shape, self.target)?;
        if Element::from_scalar(share.value) != expected {
            return Err(Error::ShareMismatch);
        }
        if let Some(existing) = self.shares.get(&share.role) {
            return if existing.expose(|value| *value) == share.value {
                Ok(())
            } else {
                Err(Error::ReplayMismatch)
            };
        }
        self.shares
            .insert(share.role, SecretScalar::new(share.value));
        drop(share);
        Ok(())
    }

    /// Produces a receipt after every mandatory share arrives.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SupportMismatch`] when any role is missing.
    pub fn finish(self) -> Result<TargetReady> {
        if self.shares.len() != self.view.command.roles.len()
            || self
                .view
                .command
                .roles
                .iter()
                .any(|role| !self.shares.contains_key(&role.role))
        {
            return Err(Error::SupportMismatch);
        }
        let value = self.shares.values().fold(Scalar::ZERO, |sum, share| {
            sum + share.expose(|value| *value)
        });
        let public = self
            .view
            .aggregate
            .evaluate(&self.view.command.shape, self.target)?;
        if Element::from_scalar(value) != public {
            return Err(Error::ShareMismatch);
        }
        Ok(TargetReady {
            receipt: TargetReceipt {
                command: self.view.command.command,
                target: self.target,
                view: self.view.bytes,
            },
            pending: PendingShare {
                target: self.target,
                share: SecretScalar::new(value),
                public,
                points: self.view.aggregate,
            },
        })
    }
}

/// One common redistribution transcript.
pub struct Candidate {
    command: Command,
    commitments: BTreeMap<RoleId, Scalar>,
    commit_closed: bool,
    openings: BTreeMap<RoleId, Opening>,
    receipts: BTreeMap<TargetId, TargetReceipt>,
    view: Option<CandidateView>,
    terminal: Option<Terminal>,
    stage: CandidateStage,
}

impl Candidate {
    /// Starts one transcript in `log`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid command replay or stale predecessor.
    pub fn new(command: Command, log: &mut impl LogAct) -> Result<Self> {
        log.begin(
            command.scope,
            command.command,
            command.predecessor,
            &command.to_bytes()?,
        )?;
        Ok(Self {
            command,
            commitments: BTreeMap::new(),
            commit_closed: false,
            openings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            view: None,
            terminal: None,
            stage: CandidateStage::Commit,
        })
    }

    /// Posts one role commitment.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown role, wrong phase, or altered replay.
    pub fn commit(
        &mut self,
        role: RoleId,
        commitment: Scalar,
        log: &mut impl LogAct,
    ) -> Result<()> {
        if let Some(existing) = self.commitments.get(&role) {
            return if *existing == commitment {
                Ok(())
            } else {
                self.abort_with(log, Error::ReplayMismatch)
            };
        }
        if self.stage != CandidateStage::Commit || self.command.role(role).is_err() {
            return self.abort_with(log, Error::WrongStage);
        }
        let mut encoder = Encoder::new();
        encoder.put_scalar(&commitment);
        if let Err(error) = log.post(
            self.command.command,
            LogPhase::Commit,
            &role.bytes(),
            &encoder.finish(),
        ) {
            return self.abort_with(log, error);
        }
        self.commitments.insert(role, commitment);
        Ok(())
    }

    /// Closes the commit phase after every role posts.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts when a role is missing.
    pub fn close_commitments(&mut self, log: &mut impl LogAct) -> Result<()> {
        if self.commit_closed {
            return Ok(());
        }
        if self.terminal.is_some() {
            return Err(Error::AlreadyTerminal);
        }
        if self.stage != CandidateStage::Commit
            || self.commitments.len() != self.command.roles.len()
            || self
                .command
                .roles
                .iter()
                .any(|role| !self.commitments.contains_key(&role.role))
        {
            return self.abort_with(log, Error::SupportMismatch);
        }
        if let Err(error) = log.close_phase(self.command.command, LogPhase::Commit) {
            return self.abort_with(log, error);
        }
        self.commit_closed = true;
        self.stage = CandidateStage::Open;
        Ok(())
    }

    /// Posts and validates one role opening.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts for an invalid opening or altered replay.
    pub fn open(&mut self, opening: Opening, log: &mut impl LogAct) -> Result<()> {
        let role = opening.role;
        if let Some(existing) = self.openings.get(&role) {
            return if existing == &opening {
                Ok(())
            } else {
                self.abort_with(log, Error::ReplayMismatch)
            };
        }
        if self.stage != CandidateStage::Open {
            return self.abort_with(log, Error::WrongStage);
        }
        let spec = match self.command.role(role) {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        let valid = opening
            .points
            .validate(&self.command.shape, spec.constant)
            .and_then(|()| {
                let commitment = self
                    .commitments
                    .get(&role)
                    .copied()
                    .ok_or(Error::CommitmentMismatch)?;
                if opening.commitment(&self.command)? == commitment {
                    Ok(())
                } else {
                    Err(Error::CommitmentMismatch)
                }
            });
        if let Err(error) = valid {
            return self.abort_with(log, error);
        }
        let bytes = match opening.to_bytes() {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        if let Err(error) = log.post(self.command.command, LogPhase::Open, &role.bytes(), &bytes) {
            return self.abort_with(log, error);
        }
        self.openings.insert(role, opening);
        Ok(())
    }

    /// Closes the opening phase and returns the common target view.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts when a role is missing.
    pub fn close_openings(&mut self, log: &mut impl LogAct) -> Result<CandidateView> {
        if let Some(view) = &self.view {
            return Ok(view.clone());
        }
        if self.stage != CandidateStage::Open
            || self.openings.len() != self.command.roles.len()
            || self
                .command
                .roles
                .iter()
                .any(|role| !self.openings.contains_key(&role.role))
        {
            return self.abort_with(log, Error::SupportMismatch);
        }
        let view = match self.build_view() {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        if let Err(error) = log.close_phase(self.command.command, LogPhase::Open) {
            return self.abort_with(log, error);
        }
        self.stage = CandidateStage::Receipt;
        self.view = Some(view.clone());
        Ok(view)
    }

    /// Posts one authenticated target receipt.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts for a changed command, view, or target.
    pub fn receipt(&mut self, receipt: TargetReceipt, log: &mut impl LogAct) -> Result<()> {
        if let Some(existing) = self.receipts.get(&receipt.target) {
            return if existing == &receipt {
                Ok(())
            } else {
                self.abort_with(log, Error::ReplayMismatch)
            };
        }
        if self.stage != CandidateStage::Receipt
            || receipt.command != self.command.command
            || !self.command.shape.targets().contains(&receipt.target)
        {
            return self.abort_with(log, Error::InvalidTranscript);
        }
        let Some(view) = &self.view else {
            return self.abort_with(log, Error::WrongStage);
        };
        if receipt.view != view.bytes {
            return self.abort_with(log, Error::InvalidTranscript);
        }
        let bytes = match receipt.to_bytes() {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        let mut role = Encoder::new();
        receipt.target.encode(&mut role);
        if let Err(error) = log.post(
            self.command.command,
            LogPhase::Receipt,
            &role.finish(),
            &bytes,
        ) {
            return self.abort_with(log, error);
        }
        self.receipts.insert(receipt.target, receipt);
        Ok(())
    }

    /// Activates after every target receipt.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts when a receipt is missing or the
    /// predecessor is stale.
    pub fn activate(&mut self, log: &mut impl LogAct) -> Result<Terminal> {
        if let Some(terminal) = self.terminal {
            return match terminal {
                Terminal::Activated(_) => Ok(terminal),
                Terminal::Aborted => Err(Error::AlreadyTerminal),
            };
        }
        self.prepare(log)?;
        match log.activate(self.command.command) {
            Ok(terminal) => {
                self.stage = CandidateStage::Terminal;
                self.terminal = Some(terminal);
                Ok(terminal)
            }
            Err(error) => self.abort_with(log, error),
        }
    }

    /// Aborts and retains the emitted prefix.
    ///
    /// # Errors
    ///
    /// Returns an error only when the transcript already activated.
    pub fn abort(&mut self, log: &mut impl LogAct) -> Result<Terminal> {
        if let Some(terminal) = self.terminal {
            return match terminal {
                Terminal::Aborted => Ok(terminal),
                Terminal::Activated(_) => Err(Error::AlreadyTerminal),
            };
        }
        let terminal = log.abort(self.command.command)?;
        self.stage = CandidateStage::Terminal;
        self.terminal = Some(terminal);
        Ok(terminal)
    }

    /// Returns the immutable command.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    fn prepare(&mut self, log: &mut impl LogAct) -> Result<()> {
        if self.stage == CandidateStage::Ready {
            return Ok(());
        }
        if self.stage != CandidateStage::Receipt
            || self.receipts.len() != self.command.shape.targets().len()
        {
            return self.abort_with(log, Error::SupportMismatch);
        }
        if let Err(error) = log.close_phase(self.command.command, LogPhase::Receipt) {
            return self.abort_with(log, error);
        }
        self.stage = CandidateStage::Ready;
        Ok(())
    }

    fn build_view(&self) -> Result<CandidateView> {
        let commitments = self
            .commitments
            .iter()
            .map(|(role, value)| (*role, *value))
            .collect::<Vec<_>>();
        let openings = self.openings.values().cloned().collect::<Vec<_>>();
        let aggregate = aggregate_points(&openings)?;
        aggregate.validate(&self.command.shape, Element::from(self.command.anchor))?;
        let bytes = encode_candidate_view(&self.command, &commitments, &openings)?;
        Ok(CandidateView {
            command: self.command.clone(),
            commitments,
            openings,
            bytes,
            aggregate,
        })
    }

    fn abort_with<T>(&mut self, log: &mut impl LogAct, error: Error) -> Result<T> {
        if let Ok(terminal) = log.abort(self.command.command) {
            self.terminal = Some(terminal);
        }
        self.stage = CandidateStage::Terminal;
        Err(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateStage {
    Commit,
    Open,
    Receipt,
    Ready,
    Terminal,
}

/// Activates several complete candidates under one terminal handle.
///
/// # Errors
///
/// Returns an error unless every candidate is ready and every predecessor is
/// current. Failure aborts every candidate that can still abort.
pub fn activate_bundle(
    candidates: &mut [&mut Candidate],
    log: &mut impl LogAct,
) -> Result<Terminal> {
    if candidates.is_empty() {
        return Err(Error::EmptyInput);
    }
    if let Some(terminal) = candidates.first().and_then(|candidate| candidate.terminal) {
        if candidates
            .iter()
            .all(|candidate| candidate.terminal == Some(terminal))
        {
            return match terminal {
                Terminal::Activated(_) => Ok(terminal),
                Terminal::Aborted => Err(Error::AlreadyTerminal),
            };
        }
        return Err(Error::AlreadyTerminal);
    }
    if candidates
        .iter()
        .any(|candidate| candidate.terminal.is_some())
    {
        return Err(Error::AlreadyTerminal);
    }
    for index in 0..candidates.len() {
        if let Err(error) = candidates[index].prepare(log) {
            for candidate in candidates.iter_mut() {
                let _ = candidate.abort(log);
            }
            return Err(error);
        }
    }
    let commands = candidates
        .iter()
        .map(|candidate| candidate.command.command)
        .collect::<Vec<_>>();
    match log.activate_bundle(&commands) {
        Ok(terminal) => {
            for candidate in candidates {
                candidate.stage = CandidateStage::Terminal;
                candidate.terminal = Some(terminal);
            }
            Ok(terminal)
        }
        Err(error) => {
            for candidate in candidates {
                let _ = candidate.abort(log);
            }
            Err(error)
        }
    }
}

fn contribution_commitment(
    command: &Command,
    role: RoleId,
    points: &ContributionPoints,
    salt: Scalar,
) -> Result<Scalar> {
    let mut encoder = Encoder::new();
    encoder.put_u8(VERSION);
    encoder.put_bytes(b"deal")?;
    encoder.put_bytes(&command.to_bytes()?)?;
    role.encode(&mut encoder);
    encoder.put_bytes(&points.to_bytes()?)?;
    encoder.put_scalar(&salt);
    hash::to_scalar(Domain::Deal, &encoder.finish())
}

fn aggregate_points(openings: &[Opening]) -> Result<ContributionPoints> {
    let (first, rest) = openings.split_first().ok_or(Error::EmptyInput)?;
    let mut aggregate = first.points.clone();
    for opening in rest {
        aggregate.add_assign(&opening.points)?;
    }
    Ok(aggregate)
}

fn encode_candidate_view(
    command: &Command,
    commitments: &[(RoleId, Scalar)],
    openings: &[Opening],
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.put_u8(VERSION);
    encoder.put_bytes(&command.to_bytes()?)?;
    encoder.put_u16(count_u16(commitments.len())?);
    for (role, commitment) in commitments {
        role.encode(&mut encoder);
        encoder.put_scalar(commitment);
    }
    encoder.put_u16(count_u16(openings.len())?);
    for opening in openings {
        encoder.put_bytes(&opening.to_bytes()?)?;
    }
    Ok(encoder.finish())
}

fn evaluate_points(points: &[Element], node: Node) -> Element {
    points
        .iter()
        .rev()
        .fold(Element::IDENTITY, |value, coefficient| {
            value * node.scalar() + *coefficient
        })
}

fn add_points(left: &mut [Element], right: &[Element]) -> Result<()> {
    if left.len() != right.len() {
        return Err(Error::LengthMismatch);
    }
    for (left, right) in left.iter_mut().zip(right) {
        *left = *left + *right;
    }
    Ok(())
}

fn encode_points(encoder: &mut Encoder, points: &[Element]) -> Result<()> {
    encoder.put_u16(count_u16(points.len())?);
    for point in points {
        encoder.put_element(*point);
    }
    Ok(())
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

fn count_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::LengthOverflow)
}
