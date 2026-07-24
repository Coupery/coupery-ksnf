use core::marker::PhantomData;
use std::collections::BTreeMap;

use frost_core::{Field, Group};

use crate::algebra::{Element, ScalarFor, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::log_act::Terminal;
use crate::profile::{DefaultProfile, Profile};
use crate::types::{ActivationHandle, CommandId};
use crate::{Error, Result};

use super::{
    Command, ContributionPoints, Opening, PrivateShare, RoleId, TargetId, TargetShape,
    expect_version,
};

type FieldOf<P> = <<P as Profile>::Group as Group>::Field;

/// A complete public opening transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct CandidateView<P: Profile = DefaultProfile> {
    pub(super) command: Command<P>,
    pub(super) commitments: Vec<(RoleId, ScalarFor<P>)>,
    pub(super) openings: Vec<Opening<P>>,
    pub(super) bytes: Vec<u8>,
    pub(super) aggregate: ContributionPoints<P>,
}

impl<P: Profile> core::fmt::Debug for CandidateView<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CandidateView")
            .field("command", &self.command)
            .field("opening_count", &self.openings.len())
            .field("aggregate", &self.aggregate)
            .finish_non_exhaustive()
    }
}

impl<P: Profile> CandidateView<P> {
    /// Returns the command.
    #[must_use]
    pub const fn command(&self) -> &Command<P> {
        &self.command
    }

    /// Returns exact common-view bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the summed public coefficient points.
    #[must_use]
    pub const fn aggregate(&self) -> &ContributionPoints<P> {
        &self.aggregate
    }

    /// Returns one role's opening.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the role is absent.
    pub fn opening(&self, role: RoleId) -> Result<&Opening<P>> {
        self.openings
            .binary_search_by_key(&role, |opening| opening.role)
            .map(|index| &self.openings[index])
            .map_err(|_| Error::ParticipantNotFound)
    }
}

/// One target's authenticated receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetReceipt<P: Profile = DefaultProfile> {
    pub(super) command: CommandId,
    pub(super) target: TargetId,
    pub(super) view: Vec<u8>,
    profile: PhantomData<P>,
}

impl<P: Profile> TargetReceipt<P> {
    /// Creates a receipt after target authentication.
    #[must_use]
    pub const fn new(command: CommandId, target: TargetId, view: Vec<u8>) -> Self {
        Self {
            command,
            target,
            view,
            profile: PhantomData,
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

    /// Returns the exact candidate-view bytes.
    #[must_use]
    pub fn view(&self) -> &[u8] {
        &self.view
    }

    /// Returns canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized view.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_u8(P::WIRE_ID);
        encoder.put_fixed(self.command.as_bytes());
        self.target.encode(&mut encoder);
        encoder.put_bytes(&self.view)?;
        Ok(encoder.finish())
    }

    /// Decodes one target receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::<P>::for_profile(bytes);
        expect_version(&mut decoder)?;
        let receipt = Self {
            command: CommandId::new(decoder.get_fixed()?),
            target: TargetId::decode(&mut decoder)?,
            view: decoder.get_bytes()?.to_vec(),
            profile: PhantomData,
        };
        decoder.finish()?;
        Ok(receipt)
    }
}

/// One target's unactivated share.
pub struct PendingShare<P: Profile = DefaultProfile> {
    target: TargetId,
    shape: TargetShape<P>,
    share: SecretScalar<P>,
    public: Element<P>,
    points: ContributionPoints<P>,
}

impl<P: Profile> PendingShare<P> {
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
    pub fn resolve(self, terminal: Terminal) -> Result<Option<InstalledShare<P>>> {
        match terminal {
            Terminal::Aborted => Ok(None),
            Terminal::Activated(handle) => {
                if Element::from_scalar(self.share.expose(|value| *value)) != self.public {
                    return Err(Error::ShareMismatch);
                }
                Ok(Some(InstalledShare {
                    target: self.target,
                    shape: self.shape,
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
pub struct InstalledShare<P: Profile = DefaultProfile> {
    target: TargetId,
    shape: TargetShape<P>,
    handle: ActivationHandle,
    share: SecretScalar<P>,
    public: Element<P>,
    points: ContributionPoints<P>,
}

impl<P: Profile> InstalledShare<P> {
    /// Returns the target.
    #[must_use]
    pub const fn target(&self) -> TargetId {
        self.target
    }

    /// Returns the installed target shape.
    #[must_use]
    pub const fn shape(&self) -> &TargetShape<P> {
        &self.shape
    }

    /// Returns the exact activation handle.
    #[must_use]
    pub const fn handle(&self) -> ActivationHandle {
        self.handle
    }

    /// Returns the public share element.
    #[must_use]
    pub const fn public(&self) -> Element<P> {
        self.public
    }

    /// Returns the installed block's public coefficient points.
    #[must_use]
    pub const fn points(&self) -> &ContributionPoints<P> {
        &self.points
    }

    /// Borrows the scalar for one operation.
    pub fn expose<T>(&self, use_share: impl FnOnce(&ScalarFor<P>) -> T) -> T {
        self.share.expose(use_share)
    }

    pub(crate) fn into_share(self) -> SecretScalar<P> {
        self.share
    }
}

impl<P: Profile> core::fmt::Debug for InstalledShare<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InstalledShare")
            .field("target", &self.target)
            .field("shape", &self.shape)
            .field("handle", &self.handle)
            .field("share", &"[REDACTED]")
            .field("public", &self.public)
            .field("points", &self.points)
            .finish()
    }
}

/// One target's receipt and pending share.
pub struct TargetReady<P: Profile = DefaultProfile> {
    receipt: TargetReceipt<P>,
    pending: PendingShare<P>,
}

impl<P: Profile> TargetReady<P> {
    /// Splits the public receipt from the private pending share.
    #[must_use]
    pub fn into_parts(self) -> (TargetReceipt<P>, PendingShare<P>) {
        (self.receipt, self.pending)
    }
}

/// A target-local private-share accumulator.
pub struct TargetAccumulator<P: Profile = DefaultProfile> {
    view: CandidateView<P>,
    target: TargetId,
    shares: BTreeMap<RoleId, SecretScalar<P>>,
}

impl<P: Profile> TargetAccumulator<P> {
    /// Starts a target-local accumulator for one complete public view.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the target is absent.
    pub fn new(view: CandidateView<P>, target: TargetId) -> Result<Self> {
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
    pub fn receive(&mut self, share: PrivateShare<P>) -> Result<()> {
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
    pub fn finish(self) -> Result<TargetReady<P>> {
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
        let value = self
            .shares
            .values()
            .fold(FieldOf::<P>::zero(), |sum, share| {
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
                profile: PhantomData,
            },
            pending: PendingShare {
                target: self.target,
                shape: self.view.command.shape.clone(),
                share: SecretScalar::new(value),
                public,
                points: self.view.aggregate,
            },
        })
    }
}
