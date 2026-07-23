//! Receiver-local authenticated deliveries.

use core::fmt;

use zeroize::Zeroizing;

use crate::algebra::Scalar;
use crate::encoding::Encoder;
use crate::hash::{self, Domain};
use crate::signing::{DeviceNonce, DeviceNonceSet, NoncePair};
use crate::support::InnerSupport;
use crate::types::{DeviceId, SessionId};
use crate::{Error, Result};

const VERSION: u8 = 1;

/// One authenticated receiver-specific commitment delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedCommitment {
    sender: DeviceId,
    receiver: DeviceId,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    commitment: Scalar,
}

impl AuthenticatedCommitment {
    /// Creates a delivery after channel authentication.
    #[must_use]
    pub fn new(
        sender: DeviceId,
        receiver: DeviceId,
        session: SessionId,
        reservation: &[u8],
        commitment: Scalar,
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
    pub const fn sender(&self) -> DeviceId {
        self.sender
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> DeviceId {
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
    pub const fn commitment(&self) -> Scalar {
        self.commitment
    }
}

impl fmt::Debug for AuthenticatedCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCommitment")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .field("commitment", &self.commitment)
            .finish()
    }
}

/// One authenticated receiver-specific nonce opening.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedOpening {
    sender: DeviceId,
    receiver: DeviceId,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    nonce: NoncePair,
}

impl AuthenticatedOpening {
    /// Creates a delivery after channel authentication.
    #[must_use]
    pub fn new(
        sender: DeviceId,
        receiver: DeviceId,
        session: SessionId,
        reservation: &[u8],
        nonce: NoncePair,
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
    pub const fn sender(&self) -> DeviceId {
        self.sender
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> DeviceId {
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
    pub const fn nonce(&self) -> NoncePair {
        self.nonce
    }
}

impl fmt::Debug for AuthenticatedOpening {
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
pub struct CommitmentView {
    receiver: DeviceId,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    entries: Vec<(DeviceId, Scalar)>,
}

impl CommitmentView {
    /// Validates and sorts a complete receiver-local commitment view.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or mismatched delivery.
    pub fn new(
        support: &InnerSupport,
        mut deliveries: Vec<AuthenticatedCommitment>,
    ) -> Result<Self> {
        deliveries.sort_unstable_by_key(|delivery| delivery.sender);
        let first = deliveries.first().ok_or(Error::EmptyInput)?;
        let receiver = first.receiver;
        let session = first.session;
        let reservation = first.reservation.clone();
        support.participant(receiver)?;
        if deliveries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        if deliveries
            .windows(2)
            .any(|pair| pair[0].sender == pair[1].sender)
        {
            return Err(Error::DuplicateParticipant);
        }
        let mut entries = Vec::with_capacity(deliveries.len());
        for (delivery, participant) in deliveries.iter().zip(support.participants()) {
            if delivery.sender != participant.device() {
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
    pub fn commitment(&self, sender: DeviceId) -> Result<Scalar> {
        self.entries
            .binary_search_by_key(&sender, |(device, _)| *device)
            .map(|index| self.entries[index].1)
            .map_err(|_| Error::ParticipantNotFound)
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> DeviceId {
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
        let mut encoder = Encoder::new();
        encode_view_prefix(
            &mut encoder,
            self.receiver,
            self.session,
            &self.reservation,
            self.entries.len(),
        )?;
        for (sender, commitment) in &self.entries {
            encoder.put_fixed(sender.as_bytes());
            encoder.put_scalar(commitment);
        }
        Ok(Zeroizing::new(encoder.finish()))
    }
}

impl fmt::Debug for CommitmentView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitmentView")
            .field("receiver", &self.receiver)
            .field("session", &self.session)
            .field("reservation", &"[REDACTED]")
            .field("entries", &self.entries)
            .finish()
    }
}

/// One fixed opening view for a receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct OpeningView {
    receiver: DeviceId,
    session: SessionId,
    reservation: Zeroizing<Vec<u8>>,
    entries: Vec<DeviceNonce>,
}

impl OpeningView {
    /// Validates and sorts a complete receiver-local opening view.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or mismatched delivery.
    pub fn new(support: &InnerSupport, mut deliveries: Vec<AuthenticatedOpening>) -> Result<Self> {
        deliveries.sort_unstable_by_key(|delivery| delivery.sender);
        let first = deliveries.first().ok_or(Error::EmptyInput)?;
        let receiver = first.receiver;
        let session = first.session;
        let reservation = first.reservation.clone();
        support.participant(receiver)?;
        if deliveries.len() != support.participants().len() {
            return Err(Error::SupportMismatch);
        }
        if deliveries
            .windows(2)
            .any(|pair| pair[0].sender == pair[1].sender)
        {
            return Err(Error::DuplicateParticipant);
        }
        let mut entries = Vec::with_capacity(deliveries.len());
        for (delivery, participant) in deliveries.iter().zip(support.participants()) {
            if delivery.sender != participant.device() {
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
        commitments: &CommitmentView,
        support: &InnerSupport,
    ) -> Result<DeviceNonceSet> {
        if self.receiver != commitments.receiver
            || self.session != commitments.session
            || self.reservation != commitments.reservation
        {
            return Err(Error::InvalidTranscript);
        }
        for entry in &self.entries {
            if nonce_commitment(entry.device(), &self.reservation, entry.nonce())?
                != commitments.commitment(entry.device())?
            {
                return Err(Error::CommitmentMismatch);
            }
        }
        DeviceNonceSet::new(support, self.entries.clone())
    }

    /// Returns the receiver.
    #[must_use]
    pub const fn receiver(&self) -> DeviceId {
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
        let mut encoder = Encoder::new();
        encode_view_prefix(
            &mut encoder,
            self.receiver,
            self.session,
            &self.reservation,
            self.entries.len(),
        )?;
        for entry in &self.entries {
            encoder.put_fixed(entry.device().as_bytes());
            encoder.put_point(entry.nonce().hiding());
            encoder.put_point(entry.nonce().binding());
        }
        Ok(Zeroizing::new(encoder.finish()))
    }
}

impl fmt::Debug for OpeningView {
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
pub fn nonce_commitment(device: DeviceId, reservation: &[u8], nonce: NoncePair) -> Result<Scalar> {
    let mut encoder = Encoder::new();
    encoder.put_u8(VERSION);
    encoder.put_bytes(b"nonce")?;
    encoder.put_fixed(device.as_bytes());
    encoder.put_bytes(reservation)?;
    encoder.put_point(nonce.hiding());
    encoder.put_point(nonce.binding());
    hash::to_scalar(Domain::Nonce, &encoder.finish())
}

fn encode_view_prefix(
    encoder: &mut Encoder,
    receiver: DeviceId,
    session: SessionId,
    reservation: &[u8],
    count: usize,
) -> Result<()> {
    encoder.put_u8(VERSION);
    encoder.put_fixed(receiver.as_bytes());
    encoder.put_fixed(session.as_bytes());
    encoder.put_bytes(reservation)?;
    encoder.put_u16(u16::try_from(count).map_err(|_| Error::LengthOverflow)?);
    Ok(())
}
