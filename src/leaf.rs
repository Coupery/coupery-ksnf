//! One-use device signing state.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::auth::{
    AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening, CommitmentView, OpeningView,
    nonce_commitment,
};
use crate::dealing::{ContributionPoints, InstalledShare, TargetId};
use crate::genesis::DeviceGenesis;
use crate::keys::KeyEpoch;
use crate::signing::{DeviceNonceSet, DeviceResponse, Nonce, NoncePair, respond_device};
use crate::transcript::{MemberReservation, MemberTranscript, RootPackage, SigningContext};
use crate::types::SessionId;
use crate::{Error, Result};

/// A live leaf stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafStage {
    /// Reservation fixed; no nonce exists.
    Reserved,
    /// Nonce exists; only its hash is public.
    Committed,
    /// The receiver's commitment view is fixed.
    Held,
    /// The receiver's complete opening view is fixed.
    Fixed,
}

/// One device's global signing lock and tombstones.
pub struct LeafRegistry {
    device: DeviceGenesis,
    epoch: KeyEpoch,
    live: Option<Live>,
    tombstones: BTreeSet<SessionId>,
}

impl LeafRegistry {
    /// Creates an idle registry for one installed key epoch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EpochMismatch`] when the handles name another device
    /// state.
    pub fn new(device: DeviceGenesis, epoch: KeyEpoch) -> Result<Self> {
        if epoch.anchor().vault() != device.vault() || epoch.anchor().person() != device.person() {
            return Err(Error::EpochMismatch);
        }
        Ok(Self {
            device,
            epoch,
            live: None,
            tombstones: BTreeSet::new(),
        })
    }

    /// Reserves the device before nonce creation.
    ///
    /// # Errors
    ///
    /// Returns an error for a busy device, closed session, altered replay, or
    /// invalid reservation.
    pub fn reserve(
        &mut self,
        session: SessionId,
        bytes: &[u8],
        outer_support: &crate::support::OuterSupport,
    ) -> Result<()> {
        if self.tombstones.contains(&session) {
            return Err(Error::Tombstoned);
        }
        if let Some(live) = &self.live {
            if live.session != session {
                return Err(Error::Busy);
            }
            if live.reservation_bytes.as_slice() == bytes {
                return Ok(());
            }
            if let Some(live) = self.live.take() {
                return self.fail(live, Error::ReplayMismatch);
            }
            return Err(Error::WrongStage);
        }

        let parsed = MemberReservation::from_bytes(bytes, outer_support).and_then(
            |(reservation, parsed_session, expiry)| {
                if parsed_session != session {
                    return Err(Error::InvalidTranscript);
                }
                if reservation.to_bytes(session, expiry)?.as_slice() != bytes {
                    return Err(Error::InvalidTranscript);
                }
                self.validate_reservation(&reservation)?;
                Ok((reservation, expiry))
            },
        );
        let (reservation, expiry) = match parsed {
            Ok(value) => value,
            Err(error) => {
                self.tombstones.insert(session);
                return Err(error);
            }
        };
        self.live = Some(Live {
            session,
            expiry,
            reservation_bytes: Zeroizing::new(bytes.to_vec()),
            reservation: Some(reservation),
            commit: None,
            reveal: None,
            fixed: None,
        });
        Ok(())
    }

    /// Samples and commits one dual nonce.
    ///
    /// Exact replay returns the cached commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for a busy device, closed session, altered replay, or
    /// wrong stage.
    pub fn commit(
        &mut self,
        session: SessionId,
        reservation_bytes: &[u8],
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<crate::algebra::Scalar> {
        let mut live = self.take_live(session)?;
        if live.reservation_bytes.as_slice() != reservation_bytes {
            return self.fail(live, Error::ReplayMismatch);
        }
        if let Some(commit) = &live.commit {
            let output = commit.commitment;
            self.live = Some(live);
            return Ok(output);
        }

        let result = (|| {
            let nonce = Nonce::sample(rng);
            let pair = nonce.commitments()?;
            let commitment = nonce_commitment(self.device.device(), reservation_bytes, pair)?;
            Ok(CommitState {
                nonce: Some(nonce),
                pair,
                commitment,
            })
        })();
        match result {
            Ok(commit) => {
                let output = commit.commitment;
                live.commit = Some(commit);
                self.live = Some(live);
                Ok(output)
            }
            Err(error) => self.fail(live, error),
        }
    }

    /// Fixes this receiver's complete commitment view and reveals its nonce.
    ///
    /// Exact replay returns the cached nonce pair.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid view, altered replay, or wrong stage.
    pub fn reveal(
        &mut self,
        session: SessionId,
        deliveries: Vec<AuthenticatedCommitment>,
    ) -> Result<NoncePair> {
        let mut live = self.take_live(session)?;
        let view = live.reservation.as_ref().map_or_else(
            || Err(Error::WrongStage),
            |reservation| CommitmentView::new(reservation.body().inner_support(), deliveries),
        );
        let view = match view {
            Ok(value) => value,
            Err(error) => return self.fail(live, error),
        };
        let bytes = match view.to_bytes() {
            Ok(value) => value,
            Err(error) => return self.fail(live, error),
        };
        if let Some(reveal) = &live.reveal {
            if reveal.bytes != bytes {
                return self.fail(live, Error::ReplayMismatch);
            }
            let pair = reveal.viewed_pair;
            self.live = Some(live);
            return Ok(pair);
        }

        let Some(commit) = &live.commit else {
            return self.fail(live, Error::WrongStage);
        };
        if view.receiver() != self.device.device()
            || view.session() != session
            || view.reservation() != live.reservation_bytes.as_slice()
        {
            return self.fail(live, Error::InvalidTranscript);
        }
        let own_commitment = match view.commitment(self.device.device()) {
            Ok(value) => value,
            Err(error) => return self.fail(live, error),
        };
        if own_commitment != commit.commitment {
            return self.fail(live, Error::CommitmentMismatch);
        }
        let pair = commit.pair;
        live.reveal = Some(RevealState {
            bytes,
            view,
            viewed_pair: pair,
        });
        self.live = Some(live);
        Ok(pair)
    }

    /// Fixes this receiver's complete opening view.
    ///
    /// Exact replay returns the cached member nonce pair.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid opening, altered replay, or wrong stage.
    pub fn fix(
        &mut self,
        session: SessionId,
        deliveries: Vec<AuthenticatedOpening>,
    ) -> Result<NoncePair> {
        let mut live = self.take_live(session)?;
        let view = live.reservation.as_ref().map_or_else(
            || Err(Error::WrongStage),
            |reservation| OpeningView::new(reservation.body().inner_support(), deliveries),
        );
        let view = match view {
            Ok(value) => value,
            Err(error) => return self.fail(live, error),
        };
        let bytes = match view.to_bytes() {
            Ok(value) => value,
            Err(error) => return self.fail(live, error),
        };
        if let Some(fixed) = &live.fixed {
            if fixed.bytes != bytes {
                return self.fail(live, Error::ReplayMismatch);
            }
            let pair = fixed.nonces.aggregate();
            self.live = Some(live);
            return Ok(pair);
        }

        let Some(reveal) = &live.reveal else {
            return self.fail(live, Error::WrongStage);
        };
        if view.receiver() != self.device.device()
            || view.session() != session
            || view.reservation() != live.reservation_bytes.as_slice()
        {
            return self.fail(live, Error::InvalidTranscript);
        }
        let Some(reservation) = live.reservation.as_ref() else {
            return self.fail(live, Error::WrongStage);
        };
        let support = reservation.body().inner_support();
        let nonces = match view.verify(&reveal.view, support) {
            Ok(value) => value,
            Err(error) => return self.fail(live, error),
        };
        let pair = nonces.aggregate();
        live.fixed = Some(FixedState { bytes, nonces });
        self.live = Some(live);
        Ok(pair)
    }

    /// Emits one response and closes the session atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid root package, nonce set, or stage. Every
    /// same-session return closes and tombstones the session.
    pub fn respond(&mut self, session: SessionId, root_bytes: &[u8]) -> Result<DeviceResponse> {
        let mut live = self.take_live(session)?;
        let result = (|| {
            let fixed = live.fixed.take().ok_or(Error::WrongStage)?;
            let commit = live.commit.as_mut().ok_or(Error::WrongStage)?;
            let nonce = commit.nonce.take().ok_or(Error::WrongStage)?;
            let reservation = live.reservation.take().ok_or(Error::WrongStage)?;
            let root = RootPackage::from_bytes(root_bytes)?;
            if root.to_bytes()?.as_slice() != root_bytes {
                return Err(Error::InvalidTranscript);
            }
            let transcript = MemberTranscript::finalize(root, reservation)?;
            let signing = SigningContext::new(transcript.root())?;
            let share = self.device.signing_share();
            respond_device(
                nonce,
                &transcript,
                &signing,
                &fixed.nonces,
                self.device.device(),
                &share,
            )
        })();
        self.tombstones.insert(session);
        drop(live);
        result
    }

    /// Closes and tombstones a session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] when another session is live.
    pub fn close(&mut self, session: SessionId) -> Result<()> {
        if self.tombstones.contains(&session) {
            return Err(Error::Tombstoned);
        }
        if let Some(live) = self.live.take() {
            if live.session != session {
                self.live = Some(live);
                return Err(Error::Busy);
            }
            drop(live);
        }
        self.tombstones.insert(session);
        Ok(())
    }

    /// Applies one authenticated sibling abort.
    ///
    /// # Errors
    ///
    /// Returns an error for another receiver, session, reservation, or sender.
    pub fn receive_abort(&mut self, abort: &AuthenticatedAbort) -> Result<()> {
        if abort.receiver() != self.device.device() {
            return Err(Error::ReceiverMismatch);
        }
        let live = self.take_live(abort.session())?;
        let valid = live.reservation.as_ref().map_or_else(
            || Err(Error::WrongStage),
            |reservation| {
                reservation
                    .body()
                    .inner_support()
                    .participant(abort.sender())?;
                if live.reservation_bytes.as_slice() == abort.reservation() {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript)
                }
            },
        );
        if let Err(error) = valid {
            return self.fail(live, error);
        }
        self.tombstones.insert(live.session);
        drop(live);
        Ok(())
    }

    /// Closes an expired live session.
    #[must_use]
    pub fn close_expired(&mut self, now: u64) -> Option<SessionId> {
        let session = self
            .live
            .as_ref()
            .filter(|live| live.expiry <= now)
            .map(|live| live.session)?;
        let live = self.live.take()?;
        drop(live);
        self.tombstones.insert(session);
        Some(session)
    }

    /// Returns the current live stage.
    #[must_use]
    pub fn stage(&self) -> Option<LeafStage> {
        self.live.as_ref().map(Live::stage)
    }

    /// Returns the live session.
    #[must_use]
    pub fn live_session(&self) -> Option<SessionId> {
        self.live.as_ref().map(|live| live.session)
    }

    /// Returns true when a session is tombstoned.
    #[must_use]
    pub fn is_tombstoned(&self, session: SessionId) -> bool {
        self.tombstones.contains(&session)
    }

    /// Atomically installs new identity and member blocks.
    ///
    /// Any live old-epoch session is closed before the new state becomes
    /// visible.
    ///
    /// # Errors
    ///
    /// Returns an error unless keys, targets, epochs, and handles match.
    pub fn activate_inner(
        &mut self,
        epoch: KeyEpoch,
        identity: InstalledShare,
        member: InstalledShare,
    ) -> Result<()> {
        let anchor = epoch.anchor();
        if anchor.vault() != self.device.vault()
            || anchor.person() != self.device.person()
            || epoch.outer() != self.epoch.outer()
            || epoch.inner() <= self.epoch.inner()
            || anchor.identity() != identity.handle()
            || anchor.member() != member.handle()
            || identity.handle() != member.handle()
            || identity.target() != TargetId::Single(self.device.device())
            || member.target() != TargetId::Single(self.device.device())
            || !matches!(identity.points(), ContributionPoints::Single(_))
            || !matches!(member.points(), ContributionPoints::Single(_))
            || identity.points().constant()?
                != crate::algebra::Element::from(self.device.identity_key().point())
            || member.points().constant()?
                != crate::algebra::Element::from(self.device.member_point().point())
        {
            return Err(Error::EpochMismatch);
        }
        self.close_live();
        self.device
            .replace_inner(identity.into_share(), member.into_share());
        self.epoch = epoch;
        Ok(())
    }

    /// Atomically installs one member block from an outer redistribution.
    ///
    /// Any live old-epoch session is closed before the new state becomes
    /// visible.
    ///
    /// # Errors
    ///
    /// Returns an error unless keys, target, epoch, and handles match.
    pub fn activate_outer(&mut self, epoch: KeyEpoch, member: InstalledShare) -> Result<()> {
        let anchor = epoch.anchor();
        let TargetId::Outer { person, device } = member.target() else {
            return Err(Error::ParticipantMismatch);
        };
        if anchor.vault() != self.device.vault()
            || anchor.person() != self.device.person()
            || person != self.device.person()
            || device != self.device.device()
            || epoch.outer() <= self.epoch.outer()
            || epoch.inner() != self.epoch.inner()
            || anchor.identity() != self.epoch.anchor().identity()
            || anchor.member() != member.handle()
            || member.points().constant()?
                != crate::algebra::Element::from(self.device.vault_key().point())
        {
            return Err(Error::EpochMismatch);
        }
        let point = crate::algebra::Point::try_from(member.points().member_constant(person)?)?;
        self.close_live();
        self.device
            .replace_member(member.into_share(), crate::keys::MemberPoint::new(point));
        self.epoch = epoch;
        Ok(())
    }

    /// Returns the installed key epoch.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    fn validate_reservation(&self, reservation: &MemberReservation) -> Result<()> {
        let body = reservation.body();
        if body.epoch() != self.epoch {
            return Err(Error::EpochMismatch);
        }
        if body.identity() != self.device.identity_key()
            || body.member() != self.device.member_point()
            || reservation.prepackage().key() != self.device.vault_key()
        {
            return Err(Error::InvalidTranscript);
        }
        let participant = body.inner_support().participant(self.device.device())?;
        if participant.node() != self.device.node() {
            return Err(Error::ParticipantMismatch);
        }
        let share = self.device.signing_share();
        let point = share.expose(|scalar| crate::algebra::Element::from_scalar(*scalar));
        if point != participant.share().element() {
            return Err(Error::ShareMismatch);
        }
        Ok(())
    }

    fn take_live(&mut self, session: SessionId) -> Result<Live> {
        if self.tombstones.contains(&session) {
            return Err(Error::Tombstoned);
        }
        let live = self.live.take().ok_or(Error::WrongStage)?;
        if live.session == session {
            Ok(live)
        } else {
            self.live = Some(live);
            Err(Error::Busy)
        }
    }

    fn fail<T>(&mut self, live: Live, error: Error) -> Result<T> {
        self.tombstones.insert(live.session);
        drop(live);
        Err(error)
    }

    fn close_live(&mut self) {
        if let Some(live) = self.live.take() {
            self.tombstones.insert(live.session);
            drop(live);
        }
    }
}

struct Live {
    session: SessionId,
    expiry: u64,
    reservation_bytes: Zeroizing<Vec<u8>>,
    reservation: Option<MemberReservation>,
    commit: Option<CommitState>,
    reveal: Option<RevealState>,
    fixed: Option<FixedState>,
}

impl Live {
    const fn stage(&self) -> LeafStage {
        if self.fixed.is_some() {
            LeafStage::Fixed
        } else if self.reveal.is_some() {
            LeafStage::Held
        } else if self.commit.is_some() {
            LeafStage::Committed
        } else {
            LeafStage::Reserved
        }
    }
}

struct CommitState {
    nonce: Option<Nonce>,
    pair: NoncePair,
    commitment: crate::algebra::Scalar,
}

struct RevealState {
    bytes: Zeroizing<Vec<u8>>,
    view: CommitmentView,
    viewed_pair: NoncePair,
}

struct FixedState {
    bytes: Zeroizing<Vec<u8>>,
    nonces: DeviceNonceSet,
}
