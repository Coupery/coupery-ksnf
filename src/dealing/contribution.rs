use k256::elliptic_curve::Field as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algebra::{Element, Scalar, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::hash::{self, Domain};
use crate::shamir::{Node, Polynomial};
use crate::types::{CommandId, DeviceId, PersonId};
use crate::{Error, Result};

use super::{Command, RoleId, RoleSpec, TargetId, TargetShape, VERSION, count_u16, expect_version};

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
                if points.len() != usize::from(target.threshold())
                    || points.first().copied() != Some(constant)
                {
                    return Err(Error::SupportMismatch);
                }
            }
            (Self::Outer { outer, members }, TargetShape::Outer(target)) => {
                if outer.len() != usize::from(target.threshold())
                    || outer.first().copied() != Some(constant)
                    || members.len() != target.people().len()
                {
                    return Err(Error::SupportMismatch);
                }
                for ((person, points), target_person) in members.iter().zip(target.people()) {
                    if *person != target_person.person()
                        || points.len() != usize::from(target_person.inner().threshold())
                        || points.first().copied()
                            != Some(evaluate_points(outer, target_person.node()))
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

    /// Decodes canonical coefficient points.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, empty, unsorted, or trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        expect_version(&mut decoder)?;
        let points = match decoder.get_u8()? {
            0 => Self::Single(decode_points(&mut decoder)?),
            1 => {
                let outer = decode_points(&mut decoder)?;
                let count = usize::from(decoder.get_u16()?);
                if count == 0 {
                    return Err(Error::EmptyInput);
                }
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push((
                        PersonId::new(decoder.get_fixed()?),
                        decode_points(&mut decoder)?,
                    ));
                }
                if members.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
                    return Err(Error::InvalidTranscript);
                }
                Self::Outer { outer, members }
            }
            _ => return Err(Error::InvalidTranscript),
        };
        decoder.finish()?;
        Ok(points)
    }

    pub(crate) fn evaluate(&self, shape: &TargetShape, target: TargetId) -> Result<Element> {
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

    pub(super) fn add_assign(&mut self, other: &Self) -> Result<()> {
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
    pub(super) role: RoleId,
    pub(super) points: ContributionPoints,
    pub(super) salt: Scalar,
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

    /// Decodes one opening.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        expect_version(&mut decoder)?;
        let role = RoleId::decode(&mut decoder)?;
        let opening = Self {
            role,
            points: ContributionPoints::from_bytes(decoder.get_bytes()?)?,
            salt: decoder.get_scalar()?,
        };
        decoder.finish()?;
        Ok(opening)
    }

    pub(super) fn commitment(&self, command: &Command) -> Result<Scalar> {
        contribution_commitment(command, self.role, &self.points, self.salt)
    }
}

/// One private scalar delivery to a target.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateShare {
    #[zeroize(skip)]
    pub(super) command: CommandId,
    #[zeroize(skip)]
    pub(super) role: RoleId,
    #[zeroize(skip)]
    pub(super) target: TargetId,
    pub(super) value: Scalar,
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
                usize::from(target.threshold()),
                constant,
                rng,
            )?)),
            TargetShape::Outer(target) => {
                let outer = Polynomial::sample(usize::from(target.threshold()), constant, rng)?;
                let mut members = Vec::with_capacity(target.people().len());
                for person in target.people() {
                    let member_constant = outer.evaluate(person.node());
                    members.push((
                        person.person(),
                        Polynomial::sample(
                            usize::from(person.inner().threshold()),
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

pub(super) fn aggregate_points(openings: &[Opening]) -> Result<ContributionPoints> {
    let (first, rest) = openings.split_first().ok_or(Error::EmptyInput)?;
    let mut aggregate = first.points.clone();
    for opening in rest {
        aggregate.add_assign(&opening.points)?;
    }
    Ok(aggregate)
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

fn decode_points(decoder: &mut Decoder<'_>) -> Result<Vec<Element>> {
    let count = usize::from(decoder.get_u16()?);
    if count == 0 {
        return Err(Error::EmptyInput);
    }
    (0..count).map(|_| decoder.get_element()).collect()
}
