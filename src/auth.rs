//! Receiver-local authenticated deliveries.

use core::fmt;

use zeroize::Zeroizing;

use crate::algebra::ScalarFor;
use crate::encoding::Encoder;
use crate::hash::{self, Domain};
use crate::profile::{DefaultProfile, Profile};
use crate::signing::{DeviceNonce, DeviceNonceSet, NoncePair};
use crate::support::InnerSupport;
use crate::types::{LeafAttempt, SessionId};
use crate::{Error, Result};

/// One authenticated receiver-specific commitment delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedCommitment<P: Profile = DefaultProfile> {
    sender: LeafAttempt,
    receiver: LeafAttempt,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    commitment: ScalarFor<P>,
}

impl<P: Profile> AuthenticatedCommitment<P> {
    /// Creates a delivery after channel authentication.
    #[must_use]
    pub fn new(
        sender: LeafAttempt,
        receiver: LeafAttempt,
        session: SessionId,
        reservation: &[u8],
        commitment: ScalarFor<P>,
    ) -> Self {
        Self {
            sender,
            receiver,
            session,
            reservation: Zeroizing::new(reservation.to_vec()),
            commitment,
        }
    }

    /// Returns the sender.
    #[must_use]
    pub const fn sender(&self) -> LeafAttempt {
        self.sender
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> LeafAttempt {
        self.receiver
    }

    /// Returns the session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Returns the exact reservation bytes.
    #[must_use]
    pub fn reservation(&self) -> &[u8] {
        &self.reservation
    }

    /// Returns the commitment scalar.
    #[must_use]
    pub const fn commitment(&self) -> ScalarFor<P> {
        self.commitment
    }
}

impl<P: Profile> fmt::Debug for AuthenticatedCommitment<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCommitment")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// One authenticated receiver-specific nonce opening.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedOpening<P: Profile = DefaultProfile> {
    sender: LeafAttempt,
    receiver: LeafAttempt,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    nonce: NoncePair<P>,
}

/// One authenticated sibling abort.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedAbort {
    sender: LeafAttempt,
    receiver: LeafAttempt,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
}

impl AuthenticatedAbort {
    /// Creates an abort after channel authentication.
    #[must_use]
    pub fn new(
        sender: LeafAttempt,
        receiver: LeafAttempt,
        session: SessionId,
        reservation: &[u8],
    ) -> Self {
        Self {
            sender,
            receiver,
            session,
            reservation: Zeroizing::new(reservation.to_vec()),
        }
    }

    /// Returns the sender.
    #[must_use]
    pub const fn sender(&self) -> LeafAttempt {
        self.sender
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> LeafAttempt {
        self.receiver
    }

    /// Returns the session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Returns the exact reservation bytes.
    #[must_use]
    pub fn reservation(&self) -> &[u8] {
        &self.reservation
    }
}

impl fmt::Debug for AuthenticatedAbort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedAbort")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .finish()
    }
}

impl<P: Profile> AuthenticatedOpening<P> {
    /// Creates a delivery after channel authentication.
    #[must_use]
    pub fn new(
        sender: LeafAttempt,
        receiver: LeafAttempt,
        session: SessionId,
        reservation: &[u8],
        nonce: NoncePair<P>,
    ) -> Self {
        Self {
            sender,
            receiver,
            session,
            reservation: Zeroizing::new(reservation.to_vec()),
            nonce,
        }
    }

    /// Returns the sender.
    #[must_use]
    pub const fn sender(&self) -> LeafAttempt {
        self.sender
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> LeafAttempt {
        self.receiver
    }

    /// Returns the session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Returns the exact reservation bytes.
    #[must_use]
    pub fn reservation(&self) -> &[u8] {
        &self.reservation
    }

    /// Returns the public nonce pair.
    #[must_use]
    pub const fn nonce(&self) -> NoncePair<P> {
        self.nonce
    }
}

impl<P: Profile> fmt::Debug for AuthenticatedOpening<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedOpening")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// One fixed commitment view for a receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct CommitmentView<P: Profile = DefaultProfile> {
    receiver: LeafAttempt,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    entries: Vec<(LeafAttempt, ScalarFor<P>)>,
}

impl<P: Profile> CommitmentView<P> {
    /// Validates and sorts a complete receiver-local commitment view.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or mismatched delivery.
    pub fn new(
        support: &InnerSupport<P>,
        mut deliveries: Vec<AuthenticatedCommitment<P>>,
    ) -> Result<Self> {
        deliveries.sort_unstable_by_key(|delivery| delivery.sender.device());
        let first = deliveries.first().ok_or(Error::EmptyInput)?;
        let receiver = first.receiver;
        let session = first.session;
        let reservation = first.reservation.clone();
        support.participant(receiver.device())?;
        if deliveries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        if deliveries
            .windows(2)
            .any(|pair| pair[0].sender.device() == pair[1].sender.device())
        {
            return Err(Error::DuplicateParticipant);
        }
        let mut entries = Vec::with_capacity(deliveries.len());
        for (delivery, participant) in deliveries.iter().zip(support.participants()) {
            if delivery.sender.device() != participant.device() {
                return Err(Error::SupportMismatch);
            }
            if delivery.receiver != receiver {
                return Err(Error::ReceiverMismatch);
            }
            if delivery.session != session || delivery.reservation != reservation {
                return Err(Error::InvalidTranscript);
            }
            entries.push((delivery.sender, delivery.commitment));
        }
        Ok(Self {
            receiver,
            session,
            reservation,
            entries,
        })
    }

    /// Returns one sender's commitment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the sender is absent.
    pub fn commitment(&self, sender: LeafAttempt) -> Result<ScalarFor<P>> {
        let index = self
            .entries
            .binary_search_by_key(&sender.device(), |(attempt, _)| attempt.device())
            .map_err(|_| Error::ParticipantNotFound)?;
        let (attempt, commitment) = self.entries[index];
        if attempt == sender {
            Ok(commitment)
        } else {
            Err(Error::AttemptMismatch)
        }
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> LeafAttempt {
        self.receiver
    }

    /// Returns the session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Returns the exact reservation bytes.
    #[must_use]
    pub fn reservation(&self) -> &[u8] {
        &self.reservation
    }

    /// Returns canonical view bytes in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized field.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut encoder = Encoder::<P>::for_profile();
        encode_view_prefix(
            &mut encoder,
            self.receiver,
            self.session,
            &self.reservation,
            self.entries.len(),
        )?;
        for (sender, commitment) in &self.entries {
            encode_attempt(&mut encoder, *sender);
            encoder.put_scalar(commitment);
        }
        Ok(Zeroizing::new(encoder.finish()))
    }
}

impl<P: Profile> fmt::Debug for CommitmentView<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitmentView")
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// One fixed opening view for a receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct OpeningView<P: Profile = DefaultProfile> {
    receiver: LeafAttempt,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    entries: Vec<DeviceNonce<P>>,
}

impl<P: Profile> OpeningView<P> {
    /// Validates and sorts a complete receiver-local opening view.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or mismatched delivery.
    pub fn new(
        support: &InnerSupport<P>,
        mut deliveries: Vec<AuthenticatedOpening<P>>,
    ) -> Result<Self> {
        deliveries.sort_unstable_by_key(|delivery| delivery.sender.device());
        let first = deliveries.first().ok_or(Error::EmptyInput)?;
        let receiver = first.receiver;
        let session = first.session;
        let reservation = first.reservation.clone();
        support.participant(receiver.device())?;
        if deliveries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        if deliveries
            .windows(2)
            .any(|pair| pair[0].sender.device() == pair[1].sender.device())
        {
            return Err(Error::DuplicateParticipant);
        }
        let mut entries = Vec::with_capacity(deliveries.len());
        for (delivery, participant) in deliveries.iter().zip(support.participants()) {
            if delivery.sender.device() != participant.device() {
                return Err(Error::SupportMismatch);
            }
            if delivery.receiver != receiver {
                return Err(Error::ReceiverMismatch);
            }
            if delivery.session != session || delivery.reservation != reservation {
                return Err(Error::InvalidTranscript);
            }
            entries.push(DeviceNonce::new(delivery.sender, delivery.nonce));
        }
        Ok(Self {
            receiver,
            session,
            reservation,
            entries,
        })
    }

    /// Checks every opening against a fixed commitment view.
    ///
    /// # Errors
    ///
    /// Returns an error when the views differ or a commitment fails.
    pub fn verify(
        &self,
        commitments: &CommitmentView<P>,
        support: &InnerSupport<P>,
    ) -> Result<DeviceNonceSet<P>> {
        if self.receiver != commitments.receiver
            || self.session != commitments.session
            || self.reservation != commitments.reservation
        {
            return Err(Error::InvalidTranscript);
        }
        for entry in &self.entries {
            if nonce_commitment(entry.attempt(), &self.reservation, entry.nonce())?
                != commitments.commitment(entry.attempt())?
            {
                return Err(Error::CommitmentMismatch);
            }
        }
        DeviceNonceSet::new(support, self.entries.clone())
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> LeafAttempt {
        self.receiver
    }

    /// Returns the session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Returns the exact reservation bytes.
    #[must_use]
    pub fn reservation(&self) -> &[u8] {
        &self.reservation
    }

    /// Returns canonical view bytes in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized field.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut encoder = Encoder::<P>::for_profile();
        encode_view_prefix(
            &mut encoder,
            self.receiver,
            self.session,
            &self.reservation,
            self.entries.len(),
        )?;
        for entry in &self.entries {
            encode_attempt(&mut encoder, entry.attempt());
            encoder.put_point(entry.nonce().hiding());
            encoder.put_point(entry.nonce().binding());
        }
        Ok(Zeroizing::new(encoder.finish()))
    }
}

impl<P: Profile> fmt::Debug for OpeningView<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpeningView")
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .field("entries", &self.entries)
            .finish()
    }
}

/// Commits a nonce pair to one device and reservation.
///
/// # Errors
///
/// Returns an error for oversized reservation bytes or hash-to-field failure.
pub fn nonce_commitment<P: Profile>(
    attempt: LeafAttempt,
    reservation: &[u8],
    nonce: NoncePair<P>,
) -> Result<ScalarFor<P>> {
    let mut encoder = Encoder::<P>::for_profile();
    encoder.put_u8(P::WIRE_ID);
    encoder.put_bytes(b"nonce")?;
    encode_attempt(&mut encoder, attempt);
    encoder.put_bytes(reservation)?;
    encoder.put_point(nonce.hiding());
    encoder.put_point(nonce.binding());
    hash::to_scalar_for::<P>(Domain::Nonce, &encoder.finish())
}

fn encode_view_prefix<P: Profile>(
    encoder: &mut Encoder<P>,
    receiver: LeafAttempt,
    session: SessionId,
    reservation: &[u8],
    count: usize,
) -> Result<()> {
    encoder.put_u8(P::WIRE_ID);
    encode_attempt(encoder, receiver);
    encoder.put_fixed(session.as_bytes());
    encoder.put_bytes(reservation)?;
    encoder.put_u16(u16::try_from(count).map_err(|_| Error::LengthOverflow)?);
    Ok(())
}

fn encode_attempt<P: Profile>(encoder: &mut Encoder<P>, attempt: LeafAttempt) {
    encoder.put_fixed(attempt.device().as_bytes());
    encoder.put_u64(attempt.sequence());
}
