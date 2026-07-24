mod persistent;
mod record;

use core::fmt;
use core::marker::PhantomData;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use self::record::{
    decode_journal, decode_material, encode_journal, encode_material, hash_material,
};
use super::LeafRegistry;
use crate::profile::{DefaultProfile, Profile};
use crate::types::{DeviceId, LeafAttempt};
use crate::{Error, Result};

pub use persistent::PersistentLeaf;

const MATERIAL_HASH_DOMAIN: &[u8] = b"KSNF/leaf-material/v1";

/// The hash of one immutable leaf-material record.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MaterialId([u8; 32]);

impl MaterialId {
    /// Creates an identifier from its bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MaterialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("MaterialId").field(&self.0).finish()
    }
}

/// Immutable secret state for one leaf.
pub struct LeafMaterial<P: Profile = DefaultProfile> {
    id: MaterialId,
    bytes: Zeroizing<Vec<u8>>,
    profile: PhantomData<P>,
}

impl<P: Profile> LeafMaterial<P> {
    /// Parses and validates a storage record.
    ///
    /// These bytes are a storage format, not a protocol encoding.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or inconsistent state.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        decode_material::<P>(&bytes)?;
        Ok(Self::from_valid_bytes(bytes))
    }

    /// Returns the content identifier.
    #[must_use]
    pub const fn id(&self) -> MaterialId {
        self.id
    }

    /// Returns the secret storage bytes.
    ///
    /// A store must protect these bytes as key material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn from_registry(registry: &LeafRegistry<P>) -> Result<Self> {
        let bytes = encode_material(registry)?;
        Ok(Self::from_valid_bytes(Zeroizing::new(bytes)))
    }

    fn from_valid_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            id: hash_material(&bytes),
            bytes,
            profile: PhantomData,
        }
    }

    fn registry(&self) -> Result<LeafRegistry<P>> {
        decode_material(&self.bytes)
    }
}

impl<P: Profile> fmt::Debug for LeafMaterial<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeafMaterial")
            .field("id", &self.id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// One journal revision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JournalRevision(u64);

impl JournalRevision {
    /// Creates a revision from its stored value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the stored value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One device's durable attempt counter and lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafJournal<P: Profile = DefaultProfile> {
    device: DeviceId,
    material: MaterialId,
    next_sequence: u64,
    live: Option<LeafAttempt>,
    profile: PhantomData<P>,
}

impl<P: Profile> LeafJournal<P> {
    /// Builds one logical journal record.
    ///
    /// # Errors
    ///
    /// Returns an error when the live attempt belongs to another device or is
    /// not the latest issued attempt.
    pub fn new(
        device: DeviceId,
        material: MaterialId,
        next_sequence: u64,
        live: Option<LeafAttempt>,
    ) -> Result<Self> {
        if let Some(attempt) = live {
            if attempt.device() != device {
                return Err(Error::ParticipantMismatch);
            }
            if attempt.sequence().checked_add(1) != Some(next_sequence) {
                return Err(Error::InvalidTranscript);
            }
        }
        Ok(Self {
            device,
            material,
            next_sequence,
            live,
            profile: PhantomData,
        })
    }

    /// Parses and validates a journal record.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or inconsistent state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_journal(bytes)
    }

    /// Encodes the fixed-size journal for storage.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 89] {
        encode_journal(self)
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// Returns the active material identifier.
    #[must_use]
    pub const fn material(&self) -> MaterialId {
        self.material
    }

    /// Returns the next sequence value.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the live attempt, if any.
    #[must_use]
    pub const fn live_attempt(&self) -> Option<LeafAttempt> {
        self.live
    }

    /// Returns true when the device has closed this attempt.
    #[must_use]
    pub fn is_closed(&self, attempt: LeafAttempt) -> bool {
        attempt.device() == self.device
            && attempt.sequence() < self.next_sequence
            && self.live != Some(attempt)
    }

    fn from_registry(material: MaterialId, registry: &LeafRegistry<P>) -> Result<Self> {
        Self::new(
            registry.device,
            material,
            registry.next_sequence,
            registry.live.as_ref().map(|live| live.attempt),
        )
    }
}

/// A journal record and its compare-and-set revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredJournal<P: Profile = DefaultProfile> {
    revision: JournalRevision,
    journal: LeafJournal<P>,
}

impl<P: Profile> StoredJournal<P> {
    /// Creates a stored journal returned by a backend.
    #[must_use]
    pub const fn new(revision: JournalRevision, journal: LeafJournal<P>) -> Self {
        Self { revision, journal }
    }

    /// Returns the revision.
    #[must_use]
    pub const fn revision(&self) -> JournalRevision {
        self.revision
    }

    /// Returns the journal.
    #[must_use]
    pub const fn journal(&self) -> &LeafJournal<P> {
        &self.journal
    }
}

/// The result of a journal compare-and-set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalCas {
    /// The next journal is durable under this revision.
    Applied(JournalRevision),
    /// The expected revision was not current.
    Conflict,
}

/// Secret material and device-journal storage for persistent leaves.
///
/// Material may use a syncable recovery store. Journals require one durable,
/// linearizable authority per physical device. Every successful write must be
/// durable before the method returns.
pub trait LeafStore<P: Profile = DefaultProfile> {
    /// The backend error.
    type Error;

    /// Stores immutable secret material.
    ///
    /// Repeating the same content-addressed write must succeed.
    ///
    /// # Errors
    ///
    /// Returns the backend error.
    fn put_material(&mut self, material: &LeafMaterial<P>)
    -> core::result::Result<(), Self::Error>;

    /// Loads immutable secret material.
    ///
    /// # Errors
    ///
    /// Returns the backend error.
    fn get_material(
        &mut self,
        id: MaterialId,
    ) -> core::result::Result<Option<LeafMaterial<P>>, Self::Error>;

    /// Loads one device's journal.
    ///
    /// # Errors
    ///
    /// Returns the backend error.
    fn get_journal(
        &mut self,
        device: DeviceId,
    ) -> core::result::Result<Option<StoredJournal<P>>, Self::Error>;

    /// Atomically replaces one device's journal at an exact revision.
    ///
    /// `None` creates the first record only when no record exists. Applied
    /// revisions must increase and never wrap.
    ///
    /// # Errors
    ///
    /// Returns the backend error. The write may have completed.
    fn compare_exchange_journal(
        &mut self,
        device: DeviceId,
        expected: Option<JournalRevision>,
        next: &LeafJournal<P>,
    ) -> core::result::Result<JournalCas, Self::Error>;
}

impl<P: Profile, T: LeafStore<P> + ?Sized> LeafStore<P> for &mut T {
    type Error = T::Error;

    fn put_material(
        &mut self,
        material: &LeafMaterial<P>,
    ) -> core::result::Result<(), Self::Error> {
        (**self).put_material(material)
    }

    fn get_material(
        &mut self,
        id: MaterialId,
    ) -> core::result::Result<Option<LeafMaterial<P>>, Self::Error> {
        (**self).get_material(id)
    }

    fn get_journal(
        &mut self,
        device: DeviceId,
    ) -> core::result::Result<Option<StoredJournal<P>>, Self::Error> {
        (**self).get_journal(device)
    }

    fn compare_exchange_journal(
        &mut self,
        device: DeviceId,
        expected: Option<JournalRevision>,
        next: &LeafJournal<P>,
    ) -> core::result::Result<JournalCas, Self::Error> {
        (**self).compare_exchange_journal(device, expected, next)
    }
}

/// An in-memory leaf store for tests and examples.
///
/// A journal update collects material no active journal references.
pub struct MemoryLeafStore<P: Profile = DefaultProfile> {
    materials: BTreeMap<MaterialId, Zeroizing<Vec<u8>>>,
    journals: BTreeMap<DeviceId, StoredJournal<P>>,
    profile: PhantomData<P>,
}

impl<P: Profile> Default for MemoryLeafStore<P> {
    fn default() -> Self {
        Self {
            materials: BTreeMap::new(),
            journals: BTreeMap::new(),
            profile: PhantomData,
        }
    }
}

impl<P: Profile> MemoryLeafStore<P> {
    /// Returns the number of retained material records.
    #[must_use]
    pub fn material_count(&self) -> usize {
        self.materials.len()
    }

    /// Returns one device's current journal.
    #[must_use]
    pub fn journal(&self, device: DeviceId) -> Option<&StoredJournal<P>> {
        self.journals.get(&device)
    }

    fn collect_material(&mut self, material: MaterialId) {
        let referenced = self
            .journals
            .values()
            .any(|stored| stored.journal().material() == material);
        if !referenced {
            self.materials.remove(&material);
        }
    }
}

impl<P: Profile> LeafStore<P> for MemoryLeafStore<P> {
    type Error = Error;

    fn put_material(&mut self, material: &LeafMaterial<P>) -> Result<()> {
        match self.materials.get(&material.id()) {
            Some(bytes) if bytes.as_slice() == material.as_bytes() => Ok(()),
            Some(_) => Err(Error::CommandMismatch),
            None => {
                self.materials
                    .insert(material.id(), Zeroizing::new(material.as_bytes().to_vec()));
                Ok(())
            }
        }
    }

    fn get_material(&mut self, id: MaterialId) -> Result<Option<LeafMaterial<P>>> {
        Ok(self
            .materials
            .get(&id)
            .map(|bytes| LeafMaterial::from_valid_bytes(Zeroizing::new(bytes.to_vec()))))
    }

    fn get_journal(&mut self, device: DeviceId) -> Result<Option<StoredJournal<P>>> {
        Ok(self.journals.get(&device).cloned())
    }

    fn compare_exchange_journal(
        &mut self,
        device: DeviceId,
        expected: Option<JournalRevision>,
        next: &LeafJournal<P>,
    ) -> Result<JournalCas> {
        if next.device() != device {
            self.collect_material(next.material());
            return Err(Error::ParticipantMismatch);
        }
        let current = self.journals.get(&device);
        let current_revision = current.map(StoredJournal::revision);
        let previous_material = current.map(|stored| stored.journal().material());
        let matches = match (expected, current_revision) {
            (None, None) => true,
            (Some(expected), Some(current)) => current == expected,
            _ => false,
        };
        if !matches {
            self.collect_material(next.material());
            return Ok(JournalCas::Conflict);
        }
        let value = match current_revision {
            Some(revision) => {
                let Some(value) = revision.get().checked_add(1) else {
                    self.collect_material(next.material());
                    return Err(Error::LengthOverflow);
                };
                value
            }
            None => 1,
        };
        let revision = JournalRevision::new(value);
        self.journals
            .insert(device, StoredJournal::new(revision, next.clone()));
        if let Some(previous) = previous_material {
            self.collect_material(previous);
        }
        Ok(JournalCas::Applied(revision))
    }
}

/// A persistent-leaf operation error.
#[derive(Debug)]
#[non_exhaustive]
pub enum PersistError<E> {
    /// A KSNF state transition failed.
    Protocol(Error),
    /// The store failed. Its write may have completed.
    Store(E),
    /// Another writer changed the device journal.
    Conflict,
    /// The journal names absent material.
    MissingMaterial(MaterialId),
    /// Stored state is malformed or inconsistent.
    InvalidRecord(Error),
    /// A prior store result must be reconciled first.
    Reconcile,
    /// The in-memory leaf can no longer be used.
    Unavailable,
}

impl<E: fmt::Display> fmt::Display for PersistError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "leaf transition: {error}"),
            Self::Store(error) => write!(formatter, "leaf store: {error}"),
            Self::Conflict => formatter.write_str("leaf journal conflict"),
            Self::MissingMaterial(_) => formatter.write_str("leaf material missing"),
            Self::InvalidRecord(error) => write!(formatter, "invalid leaf record: {error}"),
            Self::Reconcile => formatter.write_str("leaf store reconciliation required"),
            Self::Unavailable => formatter.write_str("persistent leaf unavailable"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PersistError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) | Self::InvalidRecord(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Conflict | Self::MissingMaterial(_) | Self::Reconcile | Self::Unavailable => None,
        }
    }
}

impl<E> From<Error> for PersistError<E> {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}
