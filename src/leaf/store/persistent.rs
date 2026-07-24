use super::{
    JournalCas, JournalRevision, LeafJournal, LeafMaterial, LeafStore, MaterialId, PersistError,
};
use crate::auth::{AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening};
use crate::dealing::InstalledShare;
use crate::genesis::DeviceGenesis;
use crate::keys::KeyEpoch;
use crate::leaf::LeafRegistry;
#[cfg(feature = "taproot")]
use crate::profile::Secp256k1;
use crate::profile::{DefaultProfile, Profile};
use crate::signing::{DeviceResponse, NoncePair};
use crate::support::OuterSupport;
#[cfg(feature = "taproot")]
use crate::taproot::{DeviceResponse as TaprootDeviceResponse, XOnlyKey};
use crate::types::{DeviceId, LeafAttempt, SessionId};
use crate::{Error, Result};

/// A leaf whose attempt counter, lock, and active material are durable.
pub struct PersistentLeaf<P: Profile = DefaultProfile> {
    device: DeviceId,
    registry: Option<LeafRegistry<P>>,
    material: MaterialId,
    revision: JournalRevision,
    pending: Option<PendingWrite<P>>,
}

struct PendingWrite<P: Profile = DefaultProfile> {
    previous: LeafJournal<P>,
    next: LeafJournal<P>,
    material_changed: bool,
}

impl<P: Profile> PersistentLeaf<P> {
    /// Creates the first durable record for an idle registry.
    ///
    /// # Errors
    ///
    /// Returns an error for live state, invalid material, a store failure, or
    /// an existing device journal.
    pub fn create<S: LeafStore<P> + ?Sized>(
        store: &mut S,
        registry: LeafRegistry<P>,
    ) -> core::result::Result<Self, PersistError<S::Error>> {
        let material = LeafMaterial::from_registry(&registry).map_err(PersistError::Protocol)?;
        let journal = LeafJournal::from_registry(material.id(), &registry)
            .map_err(PersistError::InvalidRecord)?;
        store.put_material(&material).map_err(PersistError::Store)?;
        let revision = match store
            .compare_exchange_journal(registry.device, None, &journal)
            .map_err(PersistError::Store)?
        {
            JournalCas::Applied(revision) => revision,
            JournalCas::Conflict => return Err(PersistError::Conflict),
        };
        Ok(Self {
            device: registry.device,
            registry: Some(registry),
            material: material.id(),
            revision,
            pending: None,
        })
    }

    /// Loads one device and closes any attempt left live by a prior process.
    ///
    /// Returns `None` when the device has no journal.
    ///
    /// # Errors
    ///
    /// Returns an error for a store failure, missing material, malformed
    /// records, or a recovery compare-and-set conflict.
    pub fn load<S: LeafStore<P> + ?Sized>(
        store: &mut S,
        device: DeviceId,
    ) -> core::result::Result<Option<Self>, PersistError<S::Error>> {
        let Some(stored) = store.get_journal(device).map_err(PersistError::Store)? else {
            return Ok(None);
        };
        if stored.journal.device != device {
            return Err(PersistError::InvalidRecord(Error::ParticipantMismatch));
        }
        let material_id = stored.journal.material;
        let material = store
            .get_material(material_id)
            .map_err(PersistError::Store)?
            .ok_or(PersistError::MissingMaterial(material_id))?;
        if material.id() != material_id {
            return Err(PersistError::InvalidRecord(Error::CommandMismatch));
        }
        let mut registry = material.registry().map_err(PersistError::InvalidRecord)?;
        if registry.device != device {
            return Err(PersistError::InvalidRecord(Error::ParticipantMismatch));
        }
        registry.next_sequence = stored.journal.next_sequence;
        let mut revision = stored.revision;
        if stored.journal.live.is_some() {
            let recovered = LeafJournal::from_registry(material_id, &registry)
                .map_err(PersistError::InvalidRecord)?;
            revision = match store
                .compare_exchange_journal(device, Some(revision), &recovered)
                .map_err(PersistError::Store)?
            {
                JournalCas::Applied(revision) => revision,
                JournalCas::Conflict => return Err(PersistError::Conflict),
            };
        }
        Ok(Some(Self {
            device,
            registry: Some(registry),
            material: material_id,
            revision,
            pending: None,
        }))
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// Returns the ready in-memory leaf.
    ///
    /// This returns `None` while reconciliation is required or after an
    /// irreconcilable conflict.
    #[must_use]
    pub const fn state(&self) -> Option<&LeafRegistry<P>> {
        if self.pending.is_none() {
            self.registry.as_ref()
        } else {
            None
        }
    }

    /// Returns true after an ambiguous store result.
    #[must_use]
    pub const fn needs_reconcile(&self) -> bool {
        self.pending.is_some()
    }

    /// Reconciles an ambiguous journal write without repeating its protocol
    /// transition.
    ///
    /// A response computed before the failed write is not recovered. Its
    /// session remains closed.
    ///
    /// # Errors
    ///
    /// Returns an error for a store failure, a concurrent journal change, or
    /// unavailable in-memory state.
    pub fn reconcile<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        let Some(pending) = self.pending.as_ref() else {
            return if self.registry.is_some() {
                Ok(())
            } else {
                Err(PersistError::Unavailable)
            };
        };
        let Some(current) = store
            .get_journal(self.device)
            .map_err(PersistError::Store)?
        else {
            self.invalidate();
            return Err(PersistError::Conflict);
        };
        if current.journal == pending.next {
            self.finish_write(current.revision);
            return Ok(());
        }
        if current.revision != self.revision {
            self.invalidate();
            return Err(PersistError::Conflict);
        }
        if current.journal != pending.previous {
            self.invalidate();
            return Err(PersistError::Conflict);
        }
        if pending.material_changed {
            let material = self.current_material()?;
            if material.id() != pending.next.material {
                self.invalidate();
                return Err(PersistError::InvalidRecord(Error::CommandMismatch));
            }
            store.put_material(&material).map_err(PersistError::Store)?;
        }
        match store
            .compare_exchange_journal(self.device, Some(self.revision), &pending.next)
            .map_err(PersistError::Store)?
        {
            JournalCas::Applied(revision) => {
                self.finish_write(revision);
                Ok(())
            }
            JournalCas::Conflict => Err(PersistError::Conflict),
        }
    }

    /// Adds a vault and persists the new immutable material.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn add_vault<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        device: DeviceGenesis<P>,
        epoch: KeyEpoch,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.material_transition(store, |registry| registry.add_vault(device, epoch))
    }

    /// Reserves the device before nonce creation.
    ///
    /// `now` must use the same clock domain as the encoded expiry.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn reserve<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        session: SessionId,
        now: u64,
        bytes: &[u8],
        outer_support: &OuterSupport<P>,
    ) -> core::result::Result<LeafAttempt, PersistError<S::Error>> {
        self.transition(store, |registry| {
            registry.reserve(session, now, bytes, outer_support)
        })
    }

    /// Samples and commits one volatile dual nonce.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn commit<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        attempt: LeafAttempt,
        reservation_bytes: &[u8],
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> core::result::Result<crate::algebra::ScalarFor<P>, PersistError<S::Error>> {
        self.transition(store, |registry| {
            registry.commit(attempt, reservation_bytes, rng)
        })
    }

    /// Fixes the receiver's commitment view and reveals its nonce.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn reveal<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        attempt: LeafAttempt,
        deliveries: Vec<AuthenticatedCommitment<P>>,
    ) -> core::result::Result<NoncePair<P>, PersistError<S::Error>> {
        self.transition(store, |registry| registry.reveal(attempt, deliveries))
    }

    /// Fixes the receiver's complete opening view.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn fix<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        attempt: LeafAttempt,
        deliveries: Vec<AuthenticatedOpening<P>>,
    ) -> core::result::Result<NoncePair<P>, PersistError<S::Error>> {
        self.transition(store, |registry| registry.fix(attempt, deliveries))
    }

    /// Emits one response after closing its durable attempt.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error. A store failure suppresses
    /// the response.
    pub fn respond<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        attempt: LeafAttempt,
        root_bytes: &[u8],
    ) -> core::result::Result<DeviceResponse<P>, PersistError<S::Error>> {
        self.transition(store, |registry| registry.respond(attempt, root_bytes))
    }

    /// Closes one attempt.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn close<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        attempt: LeafAttempt,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.transition(store, |registry| registry.close(attempt))
    }

    /// Applies one authenticated sibling abort.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn receive_abort<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        abort: &AuthenticatedAbort,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.transition(store, |registry| registry.receive_abort(abort))
    }

    /// Closes an expired live attempt.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when closure cannot be confirmed.
    pub fn close_expired<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        now: u64,
    ) -> core::result::Result<Option<LeafAttempt>, PersistError<S::Error>> {
        self.transition(store, |registry| Ok(registry.close_expired(now)))
    }

    /// Installs new identity and member blocks.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn activate_inner<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        epoch: KeyEpoch,
        identity: InstalledShare<P>,
        member: InstalledShare<P>,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.material_transition(store, |registry| {
            registry.activate_inner(epoch, identity, member)
        })
    }

    /// Installs one identity block and every vault member block.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn activate_inner_bundle<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        identity: InstalledShare<P>,
        members: Vec<(KeyEpoch, InstalledShare<P>)>,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.material_transition(store, |registry| {
            registry.activate_inner_bundle(identity, members)
        })
    }

    /// Installs one member block from an outer redistribution.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn activate_outer<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        epoch: KeyEpoch,
        member: InstalledShare<P>,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.material_transition(store, |registry| registry.activate_outer(epoch, member))
    }

    fn transition<S: LeafStore<P> + ?Sized, T>(
        &mut self,
        store: &mut S,
        operation: impl FnOnce(&mut LeafRegistry<P>) -> Result<T>,
    ) -> core::result::Result<T, PersistError<S::Error>> {
        let previous = self.ready_journal()?;
        let result = operation(self.ready_registry()?);
        let next = self.ready_journal()?;
        if next != previous {
            self.persist(store, previous, next, None)?;
        }
        result.map_err(PersistError::Protocol)
    }

    fn material_transition<S: LeafStore<P> + ?Sized, T>(
        &mut self,
        store: &mut S,
        operation: impl FnOnce(&mut LeafRegistry<P>) -> Result<T>,
    ) -> core::result::Result<T, PersistError<S::Error>> {
        let previous = self.ready_journal()?;
        let result = operation(self.ready_registry()?);
        match result {
            Ok(output) => {
                let material = match self.current_material() {
                    Ok(material) => material,
                    Err(error) => {
                        self.invalidate();
                        return Err(error);
                    }
                };
                let next = LeafJournal::from_registry(material.id(), self.ready_registry_ref()?)
                    .map_err(PersistError::InvalidRecord)?;
                self.persist(store, previous, next, Some(&material))?;
                Ok(output)
            }
            Err(error) => {
                let next = self.ready_journal()?;
                if next != previous {
                    self.persist(store, previous, next, None)?;
                }
                Err(PersistError::Protocol(error))
            }
        }
    }

    fn persist<S: LeafStore<P> + ?Sized>(
        &mut self,
        store: &mut S,
        previous: LeafJournal<P>,
        next: LeafJournal<P>,
        material: Option<&LeafMaterial<P>>,
    ) -> core::result::Result<(), PersistError<S::Error>> {
        self.pending = Some(PendingWrite {
            previous,
            next,
            material_changed: material.is_some(),
        });
        if let Some(material) = material {
            store.put_material(material).map_err(PersistError::Store)?;
        }
        let next = &self.pending.as_ref().ok_or(PersistError::Unavailable)?.next;
        match store
            .compare_exchange_journal(self.device, Some(self.revision), next)
            .map_err(PersistError::Store)?
        {
            JournalCas::Applied(revision) => {
                self.finish_write(revision);
                Ok(())
            }
            JournalCas::Conflict => Err(PersistError::Conflict),
        }
    }

    fn ready_registry<E>(&mut self) -> core::result::Result<&mut LeafRegistry<P>, PersistError<E>> {
        if self.pending.is_some() {
            return Err(PersistError::Reconcile);
        }
        self.registry.as_mut().ok_or(PersistError::Unavailable)
    }

    fn ready_registry_ref<E>(&self) -> core::result::Result<&LeafRegistry<P>, PersistError<E>> {
        if self.pending.is_some() {
            return Err(PersistError::Reconcile);
        }
        self.registry.as_ref().ok_or(PersistError::Unavailable)
    }

    fn ready_journal<E>(&self) -> core::result::Result<LeafJournal<P>, PersistError<E>> {
        LeafJournal::from_registry(self.material, self.ready_registry_ref()?)
            .map_err(PersistError::InvalidRecord)
    }

    fn current_material<E>(&self) -> core::result::Result<LeafMaterial<P>, PersistError<E>> {
        let registry = self.registry.as_ref().ok_or(PersistError::Unavailable)?;
        LeafMaterial::from_registry(registry).map_err(PersistError::InvalidRecord)
    }

    fn finish_write(&mut self, revision: JournalRevision) {
        if let Some(pending) = self.pending.take() {
            self.material = pending.next.material;
            self.revision = revision;
        }
    }

    fn invalidate(&mut self) {
        self.pending = None;
        self.registry = None;
    }
}

#[cfg(feature = "taproot")]
impl PersistentLeaf<Secp256k1> {
    /// Reserves a Taproot session under the expected output key.
    ///
    /// `now` must use the same clock domain as the encoded expiry.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error.
    pub fn reserve_taproot<S: LeafStore<Secp256k1> + ?Sized>(
        &mut self,
        store: &mut S,
        session: SessionId,
        now: u64,
        bytes: &[u8],
        expected: XOnlyKey,
        outer: &OuterSupport<Secp256k1>,
    ) -> core::result::Result<LeafAttempt, PersistError<S::Error>> {
        self.transition(store, |registry| {
            registry.reserve_taproot(session, now, bytes, expected, outer)
        })
    }

    /// Emits one Taproot response after closing its durable attempt.
    ///
    /// # Errors
    ///
    /// Returns a transition or persistence error. A store failure suppresses
    /// the response.
    pub fn respond_taproot<S: LeafStore<Secp256k1> + ?Sized>(
        &mut self,
        store: &mut S,
        attempt: LeafAttempt,
        package_bytes: &[u8],
    ) -> core::result::Result<TaprootDeviceResponse, PersistError<S::Error>> {
        self.transition(store, |registry| {
            registry.respond_taproot(attempt, package_bytes)
        })
    }
}
