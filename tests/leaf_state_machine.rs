#![allow(missing_docs)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::{LeafRegistry, LeafStage};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{MemberResponse, Nonce, Signature};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, RootContext,
    RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, SessionId, VaultId,
};
use coupery_ksnf::{Error, Result};

#[test]
fn leaf_replays_cached_values_then_tombstones() -> Result<()> {
    let mut fixture = fixture(1)?;
    fixture
        .leaf
        .reserve(fixture.session, &fixture.reservation, &fixture.outer)?;
    fixture
        .leaf
        .reserve(fixture.session, &fixture.reservation, &fixture.outer)?;
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Reserved));

    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let commitment = fixture
        .leaf
        .commit(fixture.session, &fixture.reservation, &mut rng)?;
    let mut replay_rng = ChaCha20Rng::from_seed([2; 32]);
    assert_eq!(
        fixture
            .leaf
            .commit(fixture.session, &fixture.reservation, &mut replay_rng)?,
        commitment
    );
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Committed));

    assert_eq!(
        fixture.leaf.reserve(
            SessionId::new([0xfe; 32]),
            &fixture.reservation,
            &fixture.outer,
        ),
        Err(Error::Busy)
    );
    let commitment_delivery = AuthenticatedCommitment::new(
        fixture.device,
        fixture.device,
        fixture.session,
        &fixture.reservation,
        commitment,
    );
    let pair = fixture
        .leaf
        .reveal(fixture.session, vec![commitment_delivery.clone()])?;
    assert_eq!(
        fixture
            .leaf
            .reveal(fixture.session, vec![commitment_delivery])?,
        pair
    );
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Held));

    let opening = AuthenticatedOpening::new(
        fixture.device,
        fixture.device,
        fixture.session,
        &fixture.reservation,
        pair,
    );
    assert_eq!(
        fixture.leaf.fix(fixture.session, vec![opening.clone()])?,
        pair
    );
    assert_eq!(fixture.leaf.fix(fixture.session, vec![opening])?, pair);
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Fixed));

    let root = RootPackage::finalize(
        fixture.prepackage,
        &fixture.outer,
        vec![MemberNonce::new(
            fixture.outer.participants()[0].slot(),
            pair,
        )],
    )?;
    let signing = SigningContext::new(&root)?;
    let response = fixture.leaf.respond(fixture.session, &root.to_bytes()?)?;
    let member = MemberResponse::new(fixture.outer.participants()[0].slot(), response.scalar());
    let signature = Signature::new(signing.nonce(), member.scalar());
    signature.verify(root.key(), root.message())?;
    assert_eq!(fixture.leaf.stage(), None);
    assert!(fixture.leaf.is_tombstoned(fixture.session));
    assert_eq!(
        fixture
            .leaf
            .commit(fixture.session, &fixture.reservation, &mut rng),
        Err(Error::Tombstoned)
    );
    Ok(())
}

#[test]
fn leaf_closes_on_abort_expiry_and_invalid_input() -> Result<()> {
    let mut before_commit = fixture(2)?;
    before_commit.leaf.reserve(
        before_commit.session,
        &before_commit.reservation,
        &before_commit.outer,
    )?;
    before_commit.leaf.close(before_commit.session)?;
    assert!(before_commit.leaf.is_tombstoned(before_commit.session));

    let mut altered = fixture(3)?;
    altered
        .leaf
        .reserve(altered.session, &altered.reservation, &altered.outer)?;
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    altered
        .leaf
        .commit(altered.session, &altered.reservation, &mut rng)?;
    let mut changed = altered.reservation.clone();
    changed[0] ^= 1;
    assert_eq!(
        altered.leaf.commit(altered.session, &changed, &mut rng),
        Err(Error::ReplayMismatch)
    );
    assert!(altered.leaf.is_tombstoned(altered.session));

    let mut invalid_commitment = fixture(4)?;
    invalid_commitment.leaf.reserve(
        invalid_commitment.session,
        &invalid_commitment.reservation,
        &invalid_commitment.outer,
    )?;
    let commitment = invalid_commitment.leaf.commit(
        invalid_commitment.session,
        &invalid_commitment.reservation,
        &mut rng,
    )?;
    let wrong = AuthenticatedCommitment::new(
        invalid_commitment.device,
        invalid_commitment.device,
        invalid_commitment.session,
        &invalid_commitment.reservation,
        commitment + Scalar::ONE,
    );
    assert_eq!(
        invalid_commitment
            .leaf
            .reveal(invalid_commitment.session, vec![wrong]),
        Err(Error::CommitmentMismatch)
    );
    assert!(
        invalid_commitment
            .leaf
            .is_tombstoned(invalid_commitment.session)
    );

    let mut invalid_opening = fixture(6)?;
    invalid_opening.leaf.reserve(
        invalid_opening.session,
        &invalid_opening.reservation,
        &invalid_opening.outer,
    )?;
    let commitment = invalid_opening.leaf.commit(
        invalid_opening.session,
        &invalid_opening.reservation,
        &mut rng,
    )?;
    let pair = invalid_opening.leaf.reveal(
        invalid_opening.session,
        vec![AuthenticatedCommitment::new(
            invalid_opening.device,
            invalid_opening.device,
            invalid_opening.session,
            &invalid_opening.reservation,
            commitment,
        )],
    )?;
    let wrong_pair = Nonce::new(Scalar::from(2_u64), Scalar::from(3_u64))?.commitments()?;
    assert_ne!(wrong_pair, pair);
    assert_eq!(
        invalid_opening.leaf.fix(
            invalid_opening.session,
            vec![AuthenticatedOpening::new(
                invalid_opening.device,
                invalid_opening.device,
                invalid_opening.session,
                &invalid_opening.reservation,
                wrong_pair,
            )],
        ),
        Err(Error::CommitmentMismatch)
    );
    assert!(invalid_opening.leaf.is_tombstoned(invalid_opening.session));

    let mut expired = fixture(5)?;
    expired
        .leaf
        .reserve(expired.session, &expired.reservation, &expired.outer)?;
    assert_eq!(expired.leaf.close_expired(999), Some(expired.session));
    assert!(expired.leaf.is_tombstoned(expired.session));
    Ok(())
}

#[test]
fn authenticated_sibling_abort_closes_its_receiver() -> Result<()> {
    let mut fixture = fixture(7)?;
    fixture
        .leaf
        .reserve(fixture.session, &fixture.reservation, &fixture.outer)?;
    fixture.leaf.receive_abort(&AuthenticatedAbort::new(
        fixture.device,
        fixture.device,
        fixture.session,
        &fixture.reservation,
    ))?;
    assert_eq!(fixture.leaf.stage(), None);
    assert!(fixture.leaf.is_tombstoned(fixture.session));
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
        ValidatedPublicGenesis::from_parts(vault, public_polynomial(101)?, vec![public_person])?;
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
        b"leaf state test".to_vec(),
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
