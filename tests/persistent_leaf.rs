//! Persistent leaf integration tests.

#![cfg(feature = "secp256k1")]

use core::fmt;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::genesis::{
    DeviceGenesis, PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis,
};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::{
    JournalCas, JournalRevision, LeafJournal, LeafMaterial, LeafRegistry, LeafStore, MaterialId,
    MemoryLeafStore, PersistError, PersistentLeaf, StoredJournal,
};
use coupery_ksnf::profile::Secp256k1;
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{MemberResponse, Signature};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, RootContext,
    RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId,
    SessionId, VaultId,
};
use coupery_ksnf::{Error, Result};

#[test]
fn restart_closes_the_live_attempt() -> core::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(1)?;
    let mut store = MemoryLeafStore::default();
    let mut leaf = PersistentLeaf::create(&mut store, fixture.leaf)?;
    let stored = store
        .journal(fixture.device)
        .cloned()
        .ok_or(Error::ParticipantNotFound)?;
    let journal = LeafJournal::from_bytes(&stored.journal().to_bytes())?;
    assert_eq!(journal, *stored.journal());
    let mut noncanonical = journal.to_bytes();
    assert_eq!(noncanonical.len(), 89);
    let last = noncanonical.last_mut().ok_or(Error::EmptyInput)?;
    *last = 1;
    assert_eq!(
        LeafJournal::<Secp256k1>::from_bytes(&noncanonical),
        Err(Error::InvalidTranscript)
    );
    let material = store
        .get_material(journal.material())?
        .ok_or(Error::ParticipantNotFound)?;
    let decoded = LeafMaterial::<Secp256k1>::from_bytes(material.as_bytes().to_vec())?;
    assert_eq!(decoded.id(), journal.material());
    let attempt = leaf.reserve(
        &mut store,
        fixture.session,
        0,
        &fixture.reservation,
        &fixture.outer,
    )?;
    assert_eq!(
        store
            .journal(fixture.device)
            .and_then(|stored| stored.journal().live_attempt()),
        Some(attempt)
    );

    drop(leaf);
    let leaf =
        PersistentLeaf::load(&mut store, fixture.device)?.ok_or(Error::ParticipantNotFound)?;
    let state = leaf.state().ok_or(Error::WrongStage)?;
    assert!(state.is_closed(attempt));
    assert_eq!(
        store
            .journal(fixture.device)
            .and_then(|stored| stored.journal().live_attempt()),
        None
    );
    Ok(())
}

#[test]
fn response_is_released_after_attempt_closure()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(2)?;
    let mut store = MemoryLeafStore::default();
    let mut leaf = PersistentLeaf::create(&mut store, fixture.leaf)?;
    let attempt = leaf.reserve(
        &mut store,
        fixture.session,
        0,
        &fixture.reservation,
        &fixture.outer,
    )?;
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    let commitment = leaf.commit(&mut store, attempt, &fixture.reservation, &mut rng)?;
    let pair = leaf.reveal(
        &mut store,
        attempt,
        vec![AuthenticatedCommitment::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            commitment,
        )],
    )?;
    leaf.fix(
        &mut store,
        attempt,
        vec![AuthenticatedOpening::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            pair,
        )],
    )?;
    let root = RootPackage::finalize(
        fixture.prepackage,
        &fixture.outer,
        vec![MemberNonce::new(
            fixture.outer.participants()[0].slot(),
            pair,
        )],
    )?;
    let signing = SigningContext::new(&root)?;
    let response = leaf.respond(&mut store, attempt, &root.to_bytes()?)?;
    let member =
        MemberResponse::<Secp256k1>::new(fixture.outer.participants()[0].slot(), response.scalar());
    Signature::new(signing.nonce(), member.scalar()).verify(root.key(), root.message())?;
    assert!(
        store
            .journal(fixture.device)
            .is_some_and(|stored| stored.journal().is_closed(attempt))
    );
    Ok(())
}

#[test]
fn journal_size_stays_constant_across_attempts()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(5)?;
    let mut store = MemoryLeafStore::default();
    let mut leaf = PersistentLeaf::create(&mut store, fixture.leaf)?;
    let initial_len = store
        .journal(fixture.device)
        .ok_or(Error::ParticipantNotFound)?
        .journal()
        .to_bytes()
        .len();
    let mut last: Option<LeafAttempt> = None;

    for sequence in 0..128 {
        let attempt = leaf.reserve(
            &mut store,
            fixture.session,
            0,
            &fixture.reservation,
            &fixture.outer,
        )?;
        assert_eq!(attempt.sequence(), sequence);
        assert_eq!(
            store
                .journal(fixture.device)
                .ok_or(Error::ParticipantNotFound)?
                .journal()
                .to_bytes()
                .len(),
            initial_len
        );
        leaf.close(&mut store, attempt)?;
        let journal = store
            .journal(fixture.device)
            .ok_or(Error::ParticipantNotFound)?
            .journal();
        assert_eq!(journal.to_bytes().len(), initial_len);
        assert_eq!(journal.next_sequence(), sequence + 1);
        last = Some(attempt);
    }

    let last = last.ok_or(Error::WrongStage)?;
    assert!(
        store
            .journal(fixture.device)
            .is_some_and(|stored| stored.journal().is_closed(last))
    );
    Ok(())
}

#[test]
fn ambiguous_writes_reconcile_without_repeating_transitions()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(3)?;
    let mut store = AmbiguousStore::default();
    let mut leaf = PersistentLeaf::create(&mut store, fixture.leaf)?;
    store.fail_after_apply = true;
    let error = leaf
        .reserve(
            &mut store,
            fixture.session,
            0,
            &fixture.reservation,
            &fixture.outer,
        )
        .err()
        .ok_or(Error::WrongStage)?;
    assert!(matches!(error, PersistError::Store(StoreError::Ambiguous)));
    assert!(leaf.needs_reconcile());
    assert!(leaf.state().is_none());

    leaf.reconcile(&mut store)?;
    assert!(!leaf.needs_reconcile());
    let attempt = leaf.reserve(
        &mut store,
        fixture.session,
        0,
        &fixture.reservation,
        &fixture.outer,
    )?;
    assert_eq!(
        leaf.state().and_then(LeafRegistry::live_attempt),
        Some(attempt)
    );

    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let commitment = leaf.commit(&mut store, attempt, &fixture.reservation, &mut rng)?;
    let pair = leaf.reveal(
        &mut store,
        attempt,
        vec![AuthenticatedCommitment::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            commitment,
        )],
    )?;
    leaf.fix(
        &mut store,
        attempt,
        vec![AuthenticatedOpening::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            pair,
        )],
    )?;
    let root = RootPackage::finalize(
        fixture.prepackage,
        &fixture.outer,
        vec![MemberNonce::new(
            fixture.outer.participants()[0].slot(),
            pair,
        )],
    )?;
    store.fail_after_apply = true;
    let error = leaf
        .respond(&mut store, attempt, &root.to_bytes()?)
        .err()
        .ok_or(Error::WrongStage)?;
    assert!(matches!(error, PersistError::Store(StoreError::Ambiguous)));
    leaf.reconcile(&mut store)?;
    assert!(leaf.state().is_some_and(|state| state.is_closed(attempt)));
    Ok(())
}

#[test]
fn material_change_moves_the_journal_pointer()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(4)?;
    let mut store = MemoryLeafStore::default();
    let mut leaf = PersistentLeaf::create(&mut store, fixture.leaf)?;
    let before = store
        .journal(fixture.device)
        .ok_or(Error::ParticipantNotFound)?
        .journal()
        .material();
    let (vault, device, epoch) = compatible_vault()?;
    leaf.add_vault(&mut store, device, epoch)?;
    let after = store
        .journal(fixture.device)
        .ok_or(Error::ParticipantNotFound)?
        .journal()
        .material();
    assert_ne!(before, after);
    assert_eq!(store.material_count(), 1);

    drop(leaf);
    let leaf =
        PersistentLeaf::load(&mut store, fixture.device)?.ok_or(Error::ParticipantNotFound)?;
    assert_eq!(leaf.state().ok_or(Error::WrongStage)?.epoch(vault)?, epoch);
    Ok(())
}

struct Fixture {
    leaf: LeafRegistry,
    session: SessionId,
    reservation: zeroize::Zeroizing<Vec<u8>>,
    prepackage: RootPrepackage,
    outer: coupery_ksnf::support::OuterSupport,
    device: DeviceId,
}

fn fixture(marker: u8) -> Result<Fixture> {
    let vault = VaultId::new([0x51; 32]);
    let person = PersonId::new([0x61; 32]);
    let device = DeviceId::new([0x71; 32]);
    let node = Node::from_u64(1)?;
    let public_person = PublicPerson::new(
        person,
        node,
        public_polynomial(31)?,
        public_polynomial(101)?,
        vec![PublicDevice::new(
            device,
            node,
            SharePoint::new(Point::from_scalar(Scalar::from(31_u64))?),
            SharePoint::new(Point::from_scalar(Scalar::from(101_u64))?),
        )],
    )?;
    let genesis =
        ValidatedPublicGenesis::validate(vault, public_polynomial(101)?, vec![public_person])?;
    let outer = genesis.outer_support(&[person])?;
    let inner = genesis.inner_support(person, &[device])?;
    let device_state = genesis.attach_share(
        person,
        device,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(101_u64)),
    )?;
    let epoch = KeyEpoch::new(
        OuterEpoch::new(8),
        InnerEpoch::new(9),
        AnchorId::new(
            vault,
            person,
            ActivationHandle::new([0x81; 32]),
            ActivationHandle::new([0x91; 32]),
        ),
    );
    let body = MemberBody::new(
        genesis.person(person)?.identity_key(),
        genesis.person(person)?.member_point(),
        epoch,
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(u64::from(marker) + 40));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        vec![marker; 32],
        RootContext::new(
            vault,
            epoch.outer(),
            CommandId::new([marker.wrapping_add(1); 32]),
        ),
        &outer,
        vec![record],
    )?;
    let session = SessionId::new([marker; 32]);
    let reservation =
        MemberReservation::new(prepackage.clone(), MemberOpening::new(salt, body), &outer)?
            .to_bytes(session, 100)?;
    Ok(Fixture {
        leaf: LeafRegistry::new(device_state, epoch)?,
        session,
        reservation,
        prepackage,
        outer,
        device,
    })
}

fn public_polynomial(constant: u64) -> Result<PublicPolynomial> {
    PublicPolynomial::new(vec![Element::from_scalar(Scalar::from(constant))])
}

fn compatible_vault() -> Result<(VaultId, DeviceGenesis, KeyEpoch)> {
    let vault = VaultId::new([0x52; 32]);
    let person = PersonId::new([0x61; 32]);
    let device = DeviceId::new([0x71; 32]);
    let node = Node::from_u64(1)?;
    let public_person = PublicPerson::new(
        person,
        node,
        public_polynomial(31)?,
        public_polynomial(111)?,
        vec![PublicDevice::new(
            device,
            node,
            SharePoint::new(Point::from_scalar(Scalar::from(31_u64))?),
            SharePoint::new(Point::from_scalar(Scalar::from(111_u64))?),
        )],
    )?;
    let genesis =
        ValidatedPublicGenesis::validate(vault, public_polynomial(111)?, vec![public_person])?;
    let state = genesis.attach_share(
        person,
        device,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(111_u64)),
    )?;
    let epoch = KeyEpoch::new(
        OuterEpoch::new(12),
        InnerEpoch::new(9),
        AnchorId::new(
            vault,
            person,
            ActivationHandle::new([0x81; 32]),
            ActivationHandle::new([0xa2; 32]),
        ),
    );
    Ok((vault, state, epoch))
}

#[derive(Default)]
struct AmbiguousStore {
    inner: MemoryLeafStore,
    fail_after_apply: bool,
}

#[derive(Debug)]
enum StoreError {
    Inner(Error),
    Ambiguous,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(error) => error.fmt(formatter),
            Self::Ambiguous => formatter.write_str("ambiguous write"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<Error> for StoreError {
    fn from(error: Error) -> Self {
        Self::Inner(error)
    }
}

impl LeafStore for AmbiguousStore {
    type Error = StoreError;

    fn put_material(&mut self, material: &LeafMaterial) -> core::result::Result<(), Self::Error> {
        self.inner.put_material(material).map_err(Into::into)
    }

    fn get_material(
        &mut self,
        id: MaterialId,
    ) -> core::result::Result<Option<LeafMaterial>, Self::Error> {
        self.inner.get_material(id).map_err(Into::into)
    }

    fn get_journal(
        &mut self,
        device: DeviceId,
    ) -> core::result::Result<Option<StoredJournal>, Self::Error> {
        self.inner.get_journal(device).map_err(Into::into)
    }

    fn compare_exchange_journal(
        &mut self,
        device: DeviceId,
        expected: Option<JournalRevision>,
        next: &LeafJournal,
    ) -> core::result::Result<JournalCas, Self::Error> {
        let result = self
            .inner
            .compare_exchange_journal(device, expected, next)
            .map_err(StoreError::from)?;
        if self.fail_after_apply {
            self.fail_after_apply = false;
            Err(StoreError::Ambiguous)
        } else {
            Ok(result)
        }
    }
}
