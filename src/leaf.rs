//! One-use device signing state.
//!
//! [`LeafRegistry`] is the in-memory machine. [`PersistentLeaf`] runs the same
//! transitions over an application [`LeafStore`].

mod store;

pub use store::{
    JournalCas, JournalRevision, LeafJournal, LeafMaterial, LeafStore, MaterialId, MemoryLeafStore,
    PersistError, PersistentLeaf, StoredJournal,
};

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::algebra::{Element, ScalarFor, SecretScalar};
use crate::auth::{
    AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening, CommitmentView, OpeningView,
    nonce_commitment,
};
use crate::dealing::{
    ContributionPoints, InstalledShare, OuterTarget, SingleShape, TargetId, TargetShape,
};
use crate::genesis::{
    DeviceGenesis, DeviceGenesisParts, IdentityMap, MemberMap, OuterMap, evaluate_commitments,
};
use crate::keys::{
    AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey, anchor_share, signing_share,
};
use crate::profile::{DefaultProfile, Profile};
use crate::shamir::Node;
use crate::signing::{DeviceNonceSet, DeviceResponse, Nonce, NoncePair, respond_device};
use crate::support::{InnerSupport, OuterSupport};
use crate::transcript::{MemberReservation, MemberTranscript, RootPackage, SigningContext};
use crate::types::{
    ActivationHandle, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, SessionId, VaultId,
};
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

/// One device's process-local signing lock and attempt counter.
///
/// Use [`PersistentLeaf`] when state must survive a restart.
pub struct LeafRegistry<P: Profile = DefaultProfile> {
    device: DeviceId,
    person: PersonId,
    node: Node<P>,
    identity_map: IdentityMap<P>,
    identity_key: IdentityKey<P>,
    identity: SecretScalar<P>,
    inner_epoch: InnerEpoch,
    identity_handle: ActivationHandle,
    vaults: BTreeMap<VaultId, VaultState<P>>,
    live: Option<Live<P>>,
    next_sequence: u64,
}

impl<P: Profile> LeafRegistry<P> {
    /// Creates an idle registry for one installed key epoch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EpochMismatch`] when the handles name another device
    /// state.
    pub fn new(device: DeviceGenesis<P>, epoch: KeyEpoch) -> Result<Self> {
        let parts = device.into_parts();
        validate_genesis_epoch(&parts, epoch)?;
        let mut vaults = BTreeMap::new();
        vaults.insert(
            parts.vault,
            VaultState {
                outer_node: parts.outer_node,
                outer_epoch: epoch.outer(),
                member_handle: epoch.anchor().member(),
                member_point: parts.member_point,
                vault_key: parts.vault_key,
                anchor: parts.anchor,
                member_map: parts.member_map,
                outer_map: parts.outer_map,
            },
        );
        Ok(Self {
            device: parts.device,
            person: parts.person,
            node: parts.node,
            identity_map: parts.identity_map,
            identity_key: parts.identity_key,
            identity: parts.identity,
            inner_epoch: epoch.inner(),
            identity_handle: epoch.anchor().identity(),
            vaults,
            live: None,
            next_sequence: 0,
        })
    }

    /// Creates one device registry from all active vault states.
    ///
    /// # Errors
    ///
    /// Returns an error when the list is empty or the states do not share one
    /// device, person, roster, identity sharing, and identity epoch.
    pub fn from_vaults(states: Vec<(DeviceGenesis<P>, KeyEpoch)>) -> Result<Self> {
        let mut states = states.into_iter();
        let (device, epoch) = states.next().ok_or(Error::EmptyInput)?;
        let mut registry = Self::new(device, epoch)?;
        for (device, epoch) in states {
            registry.add_vault(device, epoch)?;
        }
        Ok(registry)
    }

    /// Adds one vault that reuses the installed identity sharing.
    ///
    /// # Errors
    ///
    /// Returns an error while a session is live, for a duplicate vault, or
    /// when the device, person, roster, identity, epoch, or handle differs.
    pub fn add_vault(&mut self, device: DeviceGenesis<P>, epoch: KeyEpoch) -> Result<()> {
        if self.live.is_some() {
            return Err(Error::Busy);
        }
        let parts = device.into_parts();
        validate_genesis_epoch(&parts, epoch)?;
        let identity_public: Element<P> = parts
            .identity
            .expose(|scalar| Element::from_scalar(*scalar));
        let installed_public: Element<P> =
            self.identity.expose(|scalar| Element::from_scalar(*scalar));
        if parts.device != self.device
            || parts.person != self.person
            || parts.node != self.node
            || parts.identity_map != self.identity_map
            || parts.identity_key != self.identity_key
            || identity_public != installed_public
            || epoch.inner() != self.inner_epoch
            || epoch.anchor().identity() != self.identity_handle
            || self.vaults.contains_key(&parts.vault)
        {
            return Err(Error::EpochMismatch);
        }
        self.vaults.insert(
            parts.vault,
            VaultState {
                outer_node: parts.outer_node,
                outer_epoch: epoch.outer(),
                member_handle: epoch.anchor().member(),
                member_point: parts.member_point,
                vault_key: parts.vault_key,
                anchor: parts.anchor,
                member_map: parts.member_map,
                outer_map: parts.outer_map,
            },
        );
        Ok(())
    }

    /// Reserves the device before nonce creation.
    ///
    /// `now` must use the same clock domain as the encoded expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for a busy device, altered live replay, expired or
    /// invalid reservation, untrusted support, or exhausted counter.
    pub fn reserve(
        &mut self,
        session: SessionId,
        now: u64,
        bytes: &[u8],
        outer_support: &OuterSupport<P>,
    ) -> Result<LeafAttempt> {
        self.reserve_with(
            session,
            now,
            bytes,
            ResponseBinding::plain(),
            outer_support,
            || {
                let (reservation, parsed_session, expiry) =
                    MemberReservation::from_bytes(bytes, outer_support)?;
                if reservation.to_bytes(parsed_session, expiry)?.as_slice() != bytes {
                    return Err(Error::InvalidTranscript);
                }
                Ok((reservation, parsed_session, expiry))
            },
        )
    }

    pub(crate) fn reserve_with(
        &mut self,
        session: SessionId,
        now: u64,
        bytes: &[u8],
        response: ResponseBinding,
        outer_support: &OuterSupport<P>,
        parse: impl FnOnce() -> Result<(MemberReservation<P>, SessionId, u64)>,
    ) -> Result<LeafAttempt> {
        if let Some(live) = &self.live {
            if live.session != session {
                return Err(Error::Busy);
            }
            if live.reservation_bytes.as_slice() == bytes && live.response == response {
                return Ok(live.attempt);
            }
            if let Some(live) = self.live.take() {
                return Self::fail(live, Error::ReplayMismatch);
            }
            return Err(Error::WrongStage);
        }

        let parsed = parse().and_then(|(reservation, parsed_session, expiry)| {
            if parsed_session != session {
                return Err(Error::InvalidTranscript);
            }
            if expiry <= now {
                return Err(Error::Expired);
            }
            let vault = self.validate_reservation(&reservation, outer_support)?;
            Ok((reservation, expiry, vault))
        });
        let (reservation, expiry, vault) = parsed?;
        let attempt = self.issue_attempt()?;
        self.live = Some(Live {
            attempt,
            session,
            vault,
            expiry,
            reservation_bytes: Zeroizing::new(bytes.to_vec()),
            response,
            reservation: Some(reservation),
            commit: None,
            reveal: None,
            fixed: None,
        });
        Ok(attempt)
    }

    /// Samples and commits one dual nonce.
    ///
    /// Exact replay returns the cached commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for a busy device, closed attempt, altered replay, or
    /// wrong stage.
    pub fn commit(
        &mut self,
        attempt: LeafAttempt,
        reservation_bytes: &[u8],
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<ScalarFor<P>> {
        let mut live = self.take_live(attempt)?;
        if live.reservation_bytes.as_slice() != reservation_bytes {
            return Self::fail(live, Error::ReplayMismatch);
        }
        if let Some(commit) = &live.commit {
            let output = commit.commitment;
            self.live = Some(live);
            return Ok(output);
        }

        let result = (|| {
            let nonce = Nonce::sample(rng);
            let pair = nonce.commitments()?;
            let commitment = nonce_commitment(attempt, reservation_bytes, pair)?;
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
            Err(error) => Self::fail(live, error),
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
        attempt: LeafAttempt,
        deliveries: Vec<AuthenticatedCommitment<P>>,
    ) -> Result<NoncePair<P>> {
        let mut live = self.take_live(attempt)?;
        let view = live.reservation.as_ref().map_or_else(
            || Err(Error::WrongStage),
            |reservation| CommitmentView::new(reservation.body().inner_support(), deliveries),
        );
        let view = match view {
            Ok(value) => value,
            Err(error) => return Self::fail(live, error),
        };
        let bytes = match view.to_bytes() {
            Ok(value) => value,
            Err(error) => return Self::fail(live, error),
        };
        if let Some(reveal) = &live.reveal {
            if reveal.bytes != bytes {
                return Self::fail(live, Error::ReplayMismatch);
            }
            let pair = reveal.viewed_pair;
            self.live = Some(live);
            return Ok(pair);
        }

        let Some(commit) = &live.commit else {
            return Self::fail(live, Error::WrongStage);
        };
        if view.receiver() != attempt
            || view.session() != live.session
            || view.reservation() != live.reservation_bytes.as_slice()
        {
            return Self::fail(live, Error::InvalidTranscript);
        }
        let own_commitment = match view.commitment(attempt) {
            Ok(value) => value,
            Err(error) => return Self::fail(live, error),
        };
        if own_commitment != commit.commitment {
            return Self::fail(live, Error::CommitmentMismatch);
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
        attempt: LeafAttempt,
        deliveries: Vec<AuthenticatedOpening<P>>,
    ) -> Result<NoncePair<P>> {
        let mut live = self.take_live(attempt)?;
        let view = live.reservation.as_ref().map_or_else(
            || Err(Error::WrongStage),
            |reservation| OpeningView::new(reservation.body().inner_support(), deliveries),
        );
        let view = match view {
            Ok(value) => value,
            Err(error) => return Self::fail(live, error),
        };
        let bytes = match view.to_bytes() {
            Ok(value) => value,
            Err(error) => return Self::fail(live, error),
        };
        if let Some(fixed) = &live.fixed {
            if fixed.bytes != bytes {
                return Self::fail(live, Error::ReplayMismatch);
            }
            let pair = fixed.nonces.aggregate();
            self.live = Some(live);
            return Ok(pair);
        }

        let Some(reveal) = &live.reveal else {
            return Self::fail(live, Error::WrongStage);
        };
        if view.receiver() != attempt
            || view.session() != live.session
            || view.reservation() != live.reservation_bytes.as_slice()
        {
            return Self::fail(live, Error::InvalidTranscript);
        }
        let Some(reservation) = live.reservation.as_ref() else {
            return Self::fail(live, Error::WrongStage);
        };
        let support = reservation.body().inner_support();
        let nonces = match view.verify(&reveal.view, support) {
            Ok(value) => value,
            Err(error) => return Self::fail(live, error),
        };
        let pair = nonces.aggregate();
        live.fixed = Some(FixedState { bytes, nonces });
        self.live = Some(live);
        Ok(pair)
    }

    /// Emits one response and closes the attempt atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid root package, nonce set, or stage. Every
    /// same-attempt return closes the attempt.
    pub fn respond(
        &mut self,
        attempt: LeafAttempt,
        root_bytes: &[u8],
    ) -> Result<DeviceResponse<P>> {
        self.respond_with(attempt, ResponseMode::Plain, |input, _| {
            let root = RootPackage::from_bytes(root_bytes)?;
            if root.to_bytes()?.as_slice() != root_bytes {
                return Err(Error::InvalidTranscript);
            }
            let transcript = MemberTranscript::finalize(root, input.reservation)?;
            let signing = SigningContext::new(transcript.root())?;
            respond_device(
                input.nonce,
                &transcript,
                &signing,
                &input.nonces,
                input.device,
                &input.share,
            )
        })
    }

    pub(crate) fn respond_with<T>(
        &mut self,
        attempt: LeafAttempt,
        response_mode: ResponseMode,
        respond: impl FnOnce(ResponseInputs<P>, &[u8]) -> Result<T>,
    ) -> Result<T> {
        let mut live = self.take_live(attempt)?;
        let result = (|| {
            if live.response.mode != response_mode {
                return Err(Error::ProtocolMismatch);
            }
            let fixed = live.fixed.take().ok_or(Error::WrongStage)?;
            let commit = live.commit.as_mut().ok_or(Error::WrongStage)?;
            let nonce = commit.nonce.take().ok_or(Error::WrongStage)?;
            let reservation = live.reservation.take().ok_or(Error::WrongStage)?;
            let vault = self.vaults.get(&live.vault).ok_or(Error::EpochMismatch)?;
            let share = signing_share(&self.identity, &vault.anchor);
            respond(
                ResponseInputs {
                    nonce,
                    reservation,
                    nonces: fixed.nonces,
                    device: self.device,
                    share,
                    #[cfg(feature = "taproot")]
                    session: live.session,
                    #[cfg(feature = "taproot")]
                    expiry: live.expiry,
                },
                &live.reservation_bytes,
            )
        })();
        drop(live);
        result
    }

    /// Closes one attempt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] when another attempt is live.
    pub fn close(&mut self, attempt: LeafAttempt) -> Result<()> {
        if self.is_closed(attempt) {
            return Err(Error::AttemptClosed);
        }
        if let Some(live) = self.live.take() {
            if live.attempt != attempt {
                self.live = Some(live);
                return if attempt.device() == self.device {
                    Err(Error::Busy)
                } else {
                    Err(Error::AttemptMismatch)
                };
            }
            drop(live);
            return Ok(());
        }
        Err(Error::WrongStage)
    }

    /// Applies one authenticated sibling abort.
    ///
    /// # Errors
    ///
    /// Returns an error for another receiver, session, reservation, or sender.
    pub fn receive_abort(&mut self, abort: &AuthenticatedAbort) -> Result<()> {
        if abort.receiver().device() != self.device {
            return Err(Error::ReceiverMismatch);
        }
        if self
            .live
            .as_ref()
            .is_some_and(|live| live.attempt == abort.receiver() && live.session != abort.session())
        {
            return Err(Error::InvalidTranscript);
        }
        let live = self.take_live(abort.receiver())?;
        let valid = live.reservation.as_ref().map_or_else(
            || Err(Error::WrongStage),
            |reservation| {
                reservation
                    .body()
                    .inner_support()
                    .participant(abort.sender().device())?;
                if live.session == abort.session()
                    && live.reservation_bytes.as_slice() == abort.reservation()
                {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript)
                }
            },
        );
        if let Err(error) = valid {
            return Self::fail(live, error);
        }
        drop(live);
        Ok(())
    }

    /// Closes an expired live attempt.
    #[must_use]
    pub fn close_expired(&mut self, now: u64) -> Option<LeafAttempt> {
        let attempt = self
            .live
            .as_ref()
            .filter(|live| live.expiry <= now)
            .map(|live| live.attempt)?;
        let live = self.live.take()?;
        drop(live);
        Some(attempt)
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

    /// Returns the live attempt.
    #[must_use]
    pub fn live_attempt(&self) -> Option<LeafAttempt> {
        self.live.as_ref().map(|live| live.attempt)
    }

    /// Returns the next sequence value.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns true when the device has closed this attempt.
    #[must_use]
    pub fn is_closed(&self, attempt: LeafAttempt) -> bool {
        attempt.device() == self.device
            && attempt.sequence() < self.next_sequence
            && self
                .live
                .as_ref()
                .is_none_or(|live| live.attempt != attempt)
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
        identity: InstalledShare<P>,
        member: InstalledShare<P>,
    ) -> Result<()> {
        self.activate_inner_bundle(identity, vec![(epoch, member)])
    }

    /// Atomically installs one identity block and every vault member block.
    ///
    /// All shares must come from one terminal handle. Every active vault must
    /// appear once. Any live session closes before the new state is visible.
    ///
    /// # Errors
    ///
    /// Returns an error unless keys, targets, epochs, handles, and vaults
    /// match the installed person state.
    pub fn activate_inner_bundle(
        &mut self,
        identity: InstalledShare<P>,
        mut members: Vec<(KeyEpoch, InstalledShare<P>)>,
    ) -> Result<()> {
        members.sort_unstable_by_key(|(epoch, _)| epoch.anchor().vault());
        let handle = identity.handle();
        let identity_shape = match identity.shape() {
            TargetShape::Single(shape) => shape.clone(),
            TargetShape::Outer(_) => return Err(Error::SupportMismatch),
        };
        let next_identity_map = identity_map(&identity_shape, identity.points())?;
        let next_node = target_node(&identity_shape, self.device)?;
        if members.len() != self.vaults.len()
            || handle == self.identity_handle
            || self
                .vaults
                .values()
                .any(|vault| vault.member_handle == handle)
            || identity.target() != TargetId::Single(self.device)
            || next_node != self.node
            || identity.points().constant()? != Element::from(self.identity_key.point())
        {
            return Err(Error::EpochMismatch);
        }

        let mut next_inner = None;
        for ((epoch, member), (vault_id, vault)) in members.iter().zip(&self.vaults) {
            let anchor = epoch.anchor();
            if anchor.vault() != *vault_id
                || anchor.person() != self.person
                || epoch.outer() != vault.outer_epoch
                || epoch.inner() <= self.inner_epoch
                || next_inner.is_some_and(|inner| inner != epoch.inner())
                || anchor.identity() != handle
                || anchor.member() != handle
                || member.handle() != handle
                || member.target() != TargetId::Single(self.device)
                || member.shape() != identity.shape()
                || !matches!(member.points(), ContributionPoints::Single(_))
                || member.points().constant()? != Element::from(vault.member_point.point())
            {
                return Err(Error::EpochMismatch);
            }
            next_inner = Some(epoch.inner());
        }
        let next_inner = next_inner.ok_or(Error::EmptyInput)?;
        let next_identity = identity.into_share();
        let mut next_anchors = Vec::with_capacity(members.len());
        for (epoch, member) in members {
            let next_member_map = member_map(&identity_shape, member.points())?;
            let member = member.into_share();
            next_anchors.push((
                epoch.anchor().vault(),
                anchor_share(&member, &next_identity),
                next_member_map,
            ));
        }

        self.close_live();
        self.identity = next_identity;
        self.identity_map = next_identity_map;
        self.inner_epoch = next_inner;
        self.identity_handle = handle;
        for (state, (_, anchor, member_map)) in self.vaults.values_mut().zip(next_anchors) {
            state.anchor = anchor;
            state.member_handle = handle;
            state.member_map = member_map;
        }
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
    pub fn activate_outer(&mut self, epoch: KeyEpoch, member: InstalledShare<P>) -> Result<()> {
        let anchor = epoch.anchor();
        let TargetId::Outer { person, device } = member.target() else {
            return Err(Error::ParticipantMismatch);
        };
        let vault = self
            .vaults
            .get(&anchor.vault())
            .ok_or(Error::EpochMismatch)?;
        let TargetShape::Outer(shape) = member.shape() else {
            return Err(Error::SupportMismatch);
        };
        let target = shape
            .people()
            .binary_search_by_key(&person, OuterTarget::person)
            .map(|index| &shape.people()[index])
            .map_err(|_| Error::ParticipantNotFound)?;
        if anchor.person() != self.person
            || person != self.person
            || device != self.device
            || target.node() != vault.outer_node
            || !same_roster(&self.identity_map, target.inner())
            || epoch.outer() <= vault.outer_epoch
            || epoch.inner() != self.inner_epoch
            || anchor.identity() != self.identity_handle
            || anchor.member() != member.handle()
            || member.handle() == vault.member_handle
            || member.points().constant()? != Element::from(vault.vault_key.point())
        {
            return Err(Error::EpochMismatch);
        }
        let point = crate::algebra::Point::try_from(member.points().member_constant(person)?)?;
        let (next_outer_map, next_member_map) = outer_maps(shape, member.points(), person)?;
        let next_anchor = anchor_share(&member.into_share(), &self.identity);
        self.close_vault_live(anchor.vault());
        let vault = self
            .vaults
            .get_mut(&anchor.vault())
            .ok_or(Error::EpochMismatch)?;
        vault.outer_epoch = epoch.outer();
        vault.member_handle = anchor.member();
        vault.member_point = MemberPoint::new(point);
        vault.anchor = next_anchor;
        vault.member_map = next_member_map;
        vault.outer_map = next_outer_map;
        Ok(())
    }

    /// Returns one vault's installed key epoch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the vault is absent.
    pub fn epoch(&self, vault: VaultId) -> Result<KeyEpoch> {
        let state = self.vaults.get(&vault).ok_or(Error::ParticipantNotFound)?;
        Ok(KeyEpoch::new(
            state.outer_epoch,
            self.inner_epoch,
            AnchorId::new(
                vault,
                self.person,
                self.identity_handle,
                state.member_handle,
            ),
        ))
    }

    /// Returns the active vault identifiers.
    pub fn vaults(&self) -> impl Iterator<Item = VaultId> + '_ {
        self.vaults.keys().copied()
    }

    fn validate_reservation(
        &self,
        reservation: &MemberReservation<P>,
        outer_support: &OuterSupport<P>,
    ) -> Result<VaultId> {
        let body = reservation.body();
        let vault_id = body.epoch().anchor().vault();
        let vault = self.vaults.get(&vault_id).ok_or(Error::EpochMismatch)?;
        if body.epoch() != self.epoch(vault_id)? {
            return Err(Error::EpochMismatch);
        }
        if body.identity() != self.identity_key
            || body.member() != vault.member_point
            || reservation.prepackage().key() != vault.vault_key
        {
            return Err(Error::InvalidTranscript);
        }
        self.validate_inner_support(vault, body.inner_support())?;
        Self::validate_outer_support(vault, outer_support)?;
        let participant = body.inner_support().participant(self.device)?;
        if participant.node() != self.node {
            return Err(Error::ParticipantMismatch);
        }
        let share = signing_share(&self.identity, &vault.anchor);
        let point = share.expose(|scalar| Element::from_scalar(*scalar));
        if point != participant.share().element() {
            return Err(Error::ShareMismatch);
        }
        Ok(vault_id)
    }

    fn validate_inner_support(
        &self,
        vault: &VaultState<P>,
        support: &InnerSupport<P>,
    ) -> Result<()> {
        if support.participants().len() != vault.member_map.commitments.len() {
            return Err(Error::SupportMismatch);
        }
        let mut reconstructed = Element::identity();
        for participant in support.participants() {
            let (_, node, _) = self
                .identity_map
                .devices
                .binary_search_by_key(&participant.device(), |(device, _, _)| *device)
                .map(|index| self.identity_map.devices[index])
                .map_err(|_| Error::ParticipantNotFound)?;
            if participant.node() != node
                || participant.share().element()
                    != evaluate_commitments(&vault.member_map.commitments, node)
            {
                return Err(Error::ShareMismatch);
            }
            reconstructed = reconstructed
                + participant.share().element()
                    * support.coefficient(participant.device())?.scalar();
        }
        if reconstructed == Element::from(vault.member_point.point()) {
            Ok(())
        } else {
            Err(Error::ShareMismatch)
        }
    }

    fn validate_outer_support(vault: &VaultState<P>, support: &OuterSupport<P>) -> Result<()> {
        if support.participants().len() != vault.outer_map.commitments.len() {
            return Err(Error::SupportMismatch);
        }
        let mut reconstructed = Element::identity();
        for (index, participant) in support.participants().iter().enumerate() {
            let slot = u16::try_from(index + 1).map_err(|_| Error::LengthOverflow)?;
            let (_, node, member) = vault
                .outer_map
                .people
                .binary_search_by_key(&participant.person(), |(person, _, _)| *person)
                .map(|position| vault.outer_map.people[position])
                .map_err(|_| Error::ParticipantNotFound)?;
            if participant.slot().get() != slot
                || participant.node() != node
                || participant.member() != member
                || Element::from(member.point())
                    != evaluate_commitments(&vault.outer_map.commitments, node)
            {
                return Err(Error::ShareMismatch);
            }
            reconstructed = reconstructed
                + Element::from(member.point())
                    * support.coefficient(participant.person())?.scalar();
        }
        if reconstructed == Element::from(vault.vault_key.point()) {
            Ok(())
        } else {
            Err(Error::ShareMismatch)
        }
    }

    fn issue_attempt(&mut self) -> Result<LeafAttempt> {
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(Error::AttemptExhausted)?;
        Ok(LeafAttempt::new(self.device, sequence))
    }

    fn take_live(&mut self, attempt: LeafAttempt) -> Result<Live<P>> {
        if self.is_closed(attempt) {
            return Err(Error::AttemptClosed);
        }
        let live = self.live.take().ok_or(Error::WrongStage)?;
        if live.attempt == attempt {
            Ok(live)
        } else {
            self.live = Some(live);
            if attempt.device() == self.device {
                Err(Error::Busy)
            } else {
                Err(Error::AttemptMismatch)
            }
        }
    }

    fn fail<T>(live: Live<P>, error: Error) -> Result<T> {
        drop(live);
        Err(error)
    }

    fn close_live(&mut self) {
        if let Some(live) = self.live.take() {
            drop(live);
        }
    }

    fn close_vault_live(&mut self, vault: VaultId) {
        if self.live.as_ref().is_some_and(|live| live.vault == vault) {
            self.close_live();
        }
    }
}

pub(crate) struct ResponseInputs<P: Profile = DefaultProfile> {
    pub(crate) nonce: Nonce<P>,
    pub(crate) reservation: MemberReservation<P>,
    pub(crate) nonces: DeviceNonceSet<P>,
    pub(crate) device: DeviceId,
    pub(crate) share: SecretScalar<P>,
    #[cfg(feature = "taproot")]
    pub(crate) session: SessionId,
    #[cfg(feature = "taproot")]
    pub(crate) expiry: u64,
}

struct Live<P: Profile = DefaultProfile> {
    attempt: LeafAttempt,
    session: SessionId,
    vault: VaultId,
    expiry: u64,
    reservation_bytes: Zeroizing<Vec<u8>>,
    response: ResponseBinding,
    reservation: Option<MemberReservation<P>>,
    commit: Option<CommitState<P>>,
    reveal: Option<RevealState<P>>,
    fixed: Option<FixedState<P>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ResponseMode {
    Plain,
    #[cfg(feature = "taproot")]
    Taproot,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ResponseBinding {
    mode: ResponseMode,
    policy_tag: Option<[u8; 32]>,
}

impl ResponseBinding {
    const fn plain() -> Self {
        Self {
            mode: ResponseMode::Plain,
            policy_tag: None,
        }
    }

    #[cfg(feature = "taproot")]
    pub(crate) const fn taproot(output_key: [u8; 32]) -> Self {
        Self {
            mode: ResponseMode::Taproot,
            policy_tag: Some(output_key),
        }
    }
}

impl<P: Profile> Live<P> {
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

struct CommitState<P: Profile = DefaultProfile> {
    nonce: Option<Nonce<P>>,
    pair: NoncePair<P>,
    commitment: ScalarFor<P>,
}

struct RevealState<P: Profile = DefaultProfile> {
    bytes: Zeroizing<Vec<u8>>,
    view: CommitmentView<P>,
    viewed_pair: NoncePair<P>,
}

struct FixedState<P: Profile = DefaultProfile> {
    bytes: Zeroizing<Vec<u8>>,
    nonces: DeviceNonceSet<P>,
}

struct VaultState<P: Profile = DefaultProfile> {
    outer_node: Node<P>,
    outer_epoch: OuterEpoch,
    member_handle: ActivationHandle,
    member_point: MemberPoint<P>,
    vault_key: VaultKey<P>,
    anchor: SecretScalar<P>,
    member_map: MemberMap<P>,
    outer_map: OuterMap<P>,
}

fn validate_genesis_epoch<P: Profile>(
    parts: &DeviceGenesisParts<P>,
    epoch: KeyEpoch,
) -> Result<()> {
    if epoch.anchor().vault() == parts.vault && epoch.anchor().person() == parts.person {
        Ok(())
    } else {
        Err(Error::EpochMismatch)
    }
}

fn identity_map<P: Profile>(
    shape: &SingleShape<P>,
    points: &ContributionPoints<P>,
) -> Result<IdentityMap<P>> {
    let ContributionPoints::Single(commitments) = points else {
        return Err(Error::SupportMismatch);
    };
    if commitments.len() != usize::from(shape.threshold()) {
        return Err(Error::SupportMismatch);
    }
    let target_shape = TargetShape::Single(shape.clone());
    let devices = shape
        .devices()
        .iter()
        .map(|target| {
            let device = target.device();
            Ok((
                device,
                target.node(),
                SharePoint::new(points.evaluate(&target_shape, TargetId::Single(device))?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(IdentityMap {
        commitments: commitments.clone(),
        devices,
    })
}

fn member_map<P: Profile>(
    shape: &SingleShape<P>,
    points: &ContributionPoints<P>,
) -> Result<MemberMap<P>> {
    let ContributionPoints::Single(commitments) = points else {
        return Err(Error::SupportMismatch);
    };
    if commitments.len() != usize::from(shape.threshold()) {
        return Err(Error::SupportMismatch);
    }
    Ok(MemberMap {
        commitments: commitments.clone(),
    })
}

fn outer_maps<P: Profile>(
    shape: &crate::dealing::OuterShape<P>,
    points: &ContributionPoints<P>,
    person: PersonId,
) -> Result<(OuterMap<P>, MemberMap<P>)> {
    let ContributionPoints::Outer { outer, members } = points else {
        return Err(Error::SupportMismatch);
    };
    if outer.len() != usize::from(shape.threshold()) || members.len() != shape.people().len() {
        return Err(Error::SupportMismatch);
    }
    let people = shape
        .people()
        .iter()
        .zip(members)
        .map(|(target, (member_person, commitments))| {
            if target.person() != *member_person
                || commitments.len() != usize::from(target.inner().threshold())
            {
                return Err(Error::SupportMismatch);
            }
            let constant = commitments.first().copied().ok_or(Error::EmptyInput)?;
            Ok((
                target.person(),
                target.node(),
                MemberPoint::new(crate::algebra::Point::try_from(constant)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (_, commitments) = members
        .binary_search_by_key(&person, |(entry, _)| *entry)
        .map(|index| &members[index])
        .map_err(|_| Error::ParticipantNotFound)?;
    Ok((
        OuterMap {
            commitments: outer.clone(),
            people,
        },
        MemberMap {
            commitments: commitments.clone(),
        },
    ))
}

fn same_roster<P: Profile>(map: &IdentityMap<P>, shape: &SingleShape<P>) -> bool {
    map.commitments.len() == usize::from(shape.threshold())
        && map.devices.len() == shape.devices().len()
        && map
            .devices
            .iter()
            .zip(shape.devices())
            .all(|((device, node, _), target)| *device == target.device() && *node == target.node())
}

fn target_node<P: Profile>(shape: &SingleShape<P>, device: DeviceId) -> Result<Node<P>> {
    shape
        .devices()
        .binary_search_by_key(&device, |target| target.device())
        .map(|index| shape.devices()[index].node())
        .map_err(|_| Error::ParticipantNotFound)
}
