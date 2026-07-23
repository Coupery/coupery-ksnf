//! One-use device signing state.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::algebra::{Element, SecretScalar};
use crate::auth::{
    AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening, CommitmentView, OpeningView,
    nonce_commitment,
};
use crate::dealing::{
    ContributionPoints, InstalledShare, OuterTarget, SingleShape, TargetId, TargetShape,
};
use crate::genesis::{DeviceGenesis, DeviceGenesisParts, IdentityMap};
use crate::keys::{
    AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey, anchor_share, signing_share,
};
use crate::shamir::Node;
use crate::signing::{DeviceNonceSet, DeviceResponse, Nonce, NoncePair, respond_device};
use crate::transcript::{MemberReservation, MemberTranscript, RootPackage, SigningContext};
use crate::types::{
    ActivationHandle, DeviceId, InnerEpoch, OuterEpoch, PersonId, SessionId, VaultId,
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

/// One device's global signing lock and tombstones.
pub struct LeafRegistry {
    device: DeviceId,
    person: PersonId,
    node: Node,
    identity_map: IdentityMap,
    identity_key: IdentityKey,
    identity: SecretScalar,
    inner_epoch: InnerEpoch,
    identity_handle: ActivationHandle,
    vaults: BTreeMap<VaultId, VaultState>,
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
            tombstones: BTreeSet::new(),
        })
    }

    /// Creates one device registry from all active vault states.
    ///
    /// # Errors
    ///
    /// Returns an error when the list is empty or the states do not share one
    /// device, person, roster, identity sharing, and identity epoch.
    pub fn from_vaults(states: Vec<(DeviceGenesis, KeyEpoch)>) -> Result<Self> {
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
    pub fn add_vault(&mut self, device: DeviceGenesis, epoch: KeyEpoch) -> Result<()> {
        if self.live.is_some() {
            return Err(Error::Busy);
        }
        let parts = device.into_parts();
        validate_genesis_epoch(&parts, epoch)?;
        let identity_public = parts
            .identity
            .expose(|scalar| Element::from_scalar(*scalar));
        let installed_public = self.identity.expose(|scalar| Element::from_scalar(*scalar));
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
            },
        );
        Ok(())
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
                let vault = self.validate_reservation(&reservation)?;
                Ok((reservation, expiry, vault))
            },
        );
        let (reservation, expiry, vault) = match parsed {
            Ok(value) => value,
            Err(error) => {
                self.tombstones.insert(session);
                return Err(error);
            }
        };
        self.live = Some(Live {
            session,
            vault,
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
            let commitment = nonce_commitment(self.device, reservation_bytes, pair)?;
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
        if view.receiver() != self.device
            || view.session() != session
            || view.reservation() != live.reservation_bytes.as_slice()
        {
            return self.fail(live, Error::InvalidTranscript);
        }
        let own_commitment = match view.commitment(self.device) {
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
        if view.receiver() != self.device
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
            let vault = self.vaults.get(&live.vault).ok_or(Error::EpochMismatch)?;
            let share = signing_share(&self.identity, &vault.anchor);
            respond_device(
                nonce,
                &transcript,
                &signing,
                &fixed.nonces,
                self.device,
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
        if abort.receiver() != self.device {
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
        identity: InstalledShare,
        mut members: Vec<(KeyEpoch, InstalledShare)>,
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
            let member = member.into_share();
            next_anchors.push((
                epoch.anchor().vault(),
                anchor_share(&member, &next_identity),
            ));
        }

        self.close_live();
        self.identity = next_identity;
        self.identity_map = next_identity_map;
        self.inner_epoch = next_inner;
        self.identity_handle = handle;
        for (state, (_, anchor)) in self.vaults.values_mut().zip(next_anchors) {
            state.anchor = anchor;
            state.member_handle = handle;
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
    pub fn activate_outer(&mut self, epoch: KeyEpoch, member: InstalledShare) -> Result<()> {
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

    fn validate_reservation(&self, reservation: &MemberReservation) -> Result<VaultId> {
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

    fn close_vault_live(&mut self, vault: VaultId) {
        if self.live.as_ref().is_some_and(|live| live.vault == vault) {
            self.close_live();
        }
    }
}

struct Live {
    session: SessionId,
    vault: VaultId,
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

struct VaultState {
    outer_node: Node,
    outer_epoch: OuterEpoch,
    member_handle: ActivationHandle,
    member_point: MemberPoint,
    vault_key: VaultKey,
    anchor: SecretScalar,
}

fn validate_genesis_epoch(parts: &DeviceGenesisParts, epoch: KeyEpoch) -> Result<()> {
    if epoch.anchor().vault() == parts.vault && epoch.anchor().person() == parts.person {
        Ok(())
    } else {
        Err(Error::EpochMismatch)
    }
}

fn identity_map(shape: &SingleShape, points: &ContributionPoints) -> Result<IdentityMap> {
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

fn same_roster(map: &IdentityMap, shape: &SingleShape) -> bool {
    map.commitments.len() == usize::from(shape.threshold())
        && map.devices.len() == shape.devices().len()
        && map
            .devices
            .iter()
            .zip(shape.devices())
            .all(|((device, node, _), target)| *device == target.device() && *node == target.node())
}

fn target_node(shape: &SingleShape, device: DeviceId) -> Result<Node> {
    shape
        .devices()
        .binary_search_by_key(&device, |target| target.device())
        .map(|index| shape.devices()[index].node())
        .map_err(|_| Error::ParticipantNotFound)
}
