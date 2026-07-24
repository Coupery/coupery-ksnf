//! Leaf state-machine tests.

#![cfg(feature = "secp256k1")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::{LeafRegistry, LeafStage};
use coupery_ksnf::profile::Secp256k1;
use coupery_ksnf::shamir::Node;
#[cfg(feature = "taproot")]
use coupery_ksnf::signing::NoncePair;
use coupery_ksnf::signing::{MemberResponse, Nonce, Signature};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
#[cfg(feature = "taproot")]
use coupery_ksnf::taproot::{Key, MemberResponse as TaprootMemberResponse, Package, Reservation};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, RootContext,
    RootPackage, RootPrepackage, SigningContext,
};
#[cfg(feature = "taproot")]
use coupery_ksnf::types::LeafAttempt;
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, SessionId, VaultId,
};
use coupery_ksnf::{Error, Result};

#[test]
fn leaf_replays_cached_values_then_closes_attempt() -> Result<()> {
    let mut fixture = fixture(1)?;
    let attempt = fixture
        .leaf
        .reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?;
    assert_eq!(
        fixture
            .leaf
            .reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?,
        attempt
    );
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Reserved));

    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let commitment = fixture
        .leaf
        .commit(attempt, &fixture.reservation, &mut rng)?;
    let mut replay_rng = ChaCha20Rng::from_seed([2; 32]);
    assert_eq!(
        fixture
            .leaf
            .commit(attempt, &fixture.reservation, &mut replay_rng)?,
        commitment
    );
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Committed));

    assert_eq!(
        fixture.leaf.reserve(
            SessionId::new([0xfe; 32]),
            0,
            &fixture.reservation,
            &fixture.outer,
        ),
        Err(Error::Busy)
    );
    let commitment_delivery = AuthenticatedCommitment::new(
        attempt,
        attempt,
        fixture.session,
        &fixture.reservation,
        commitment,
    );
    let pair = fixture
        .leaf
        .reveal(attempt, vec![commitment_delivery.clone()])?;
    assert_eq!(
        fixture.leaf.reveal(attempt, vec![commitment_delivery])?,
        pair
    );
    assert_eq!(fixture.leaf.stage(), Some(LeafStage::Held));

    let opening = AuthenticatedOpening::new(
        attempt,
        attempt,
        fixture.session,
        &fixture.reservation,
        pair,
    );
    assert_eq!(fixture.leaf.fix(attempt, vec![opening.clone()])?, pair);
    assert_eq!(fixture.leaf.fix(attempt, vec![opening])?, pair);
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
    let response = fixture.leaf.respond(attempt, &root.to_bytes()?)?;
    let member =
        MemberResponse::<Secp256k1>::new(fixture.outer.participants()[0].slot(), response.scalar());
    let signature = Signature::new(signing.nonce(), member.scalar());
    signature.verify(root.key(), root.message())?;
    assert_eq!(fixture.leaf.stage(), None);
    assert!(fixture.leaf.is_closed(attempt));
    assert_eq!(
        fixture.leaf.commit(attempt, &fixture.reservation, &mut rng),
        Err(Error::AttemptClosed)
    );
    Ok(())
}

#[test]
fn leaf_closes_on_abort_expiry_and_invalid_input() -> Result<()> {
    let mut before_commit = fixture(2)?;
    let before_attempt = before_commit.leaf.reserve(
        before_commit.session,
        0,
        &before_commit.reservation,
        &before_commit.outer,
    )?;
    before_commit.leaf.close(before_attempt)?;
    assert!(before_commit.leaf.is_closed(before_attempt));

    let mut altered = fixture(3)?;
    let altered_attempt =
        altered
            .leaf
            .reserve(altered.session, 0, &altered.reservation, &altered.outer)?;
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    altered
        .leaf
        .commit(altered_attempt, &altered.reservation, &mut rng)?;
    let mut changed = altered.reservation.clone();
    changed[0] ^= 1;
    assert_eq!(
        altered.leaf.commit(altered_attempt, &changed, &mut rng),
        Err(Error::ReplayMismatch)
    );
    assert!(altered.leaf.is_closed(altered_attempt));

    let mut invalid_commitment = fixture(4)?;
    let commitment_attempt = invalid_commitment.leaf.reserve(
        invalid_commitment.session,
        0,
        &invalid_commitment.reservation,
        &invalid_commitment.outer,
    )?;
    let commitment = invalid_commitment.leaf.commit(
        commitment_attempt,
        &invalid_commitment.reservation,
        &mut rng,
    )?;
    let wrong = AuthenticatedCommitment::new(
        commitment_attempt,
        commitment_attempt,
        invalid_commitment.session,
        &invalid_commitment.reservation,
        commitment + Scalar::ONE,
    );
    assert_eq!(
        invalid_commitment
            .leaf
            .reveal(commitment_attempt, vec![wrong]),
        Err(Error::CommitmentMismatch)
    );
    assert!(invalid_commitment.leaf.is_closed(commitment_attempt));

    let mut invalid_opening = fixture(6)?;
    let opening_attempt = invalid_opening.leaf.reserve(
        invalid_opening.session,
        0,
        &invalid_opening.reservation,
        &invalid_opening.outer,
    )?;
    let commitment =
        invalid_opening
            .leaf
            .commit(opening_attempt, &invalid_opening.reservation, &mut rng)?;
    let pair = invalid_opening.leaf.reveal(
        opening_attempt,
        vec![AuthenticatedCommitment::new(
            opening_attempt,
            opening_attempt,
            invalid_opening.session,
            &invalid_opening.reservation,
            commitment,
        )],
    )?;
    let wrong_pair = Nonce::new(Scalar::from(2_u64), Scalar::from(3_u64))?.commitments()?;
    assert_ne!(wrong_pair, pair);
    assert_eq!(
        invalid_opening.leaf.fix(
            opening_attempt,
            vec![AuthenticatedOpening::new(
                opening_attempt,
                opening_attempt,
                invalid_opening.session,
                &invalid_opening.reservation,
                wrong_pair,
            )],
        ),
        Err(Error::CommitmentMismatch)
    );
    assert!(invalid_opening.leaf.is_closed(opening_attempt));

    let mut expired = fixture(5)?;
    let expired_attempt =
        expired
            .leaf
            .reserve(expired.session, 0, &expired.reservation, &expired.outer)?;
    assert_eq!(expired.leaf.close_expired(999), Some(expired_attempt));
    assert!(expired.leaf.is_closed(expired_attempt));
    Ok(())
}

#[test]
fn reserve_rejects_expiry_and_untrusted_supports_before_nonce() -> Result<()> {
    let mut expired = fixture(13)?;
    assert_eq!(
        expired
            .leaf
            .reserve(expired.session, 100, &expired.reservation, &expired.outer,),
        Err(Error::Expired)
    );
    assert_eq!(expired.leaf.next_sequence(), 0);

    let mut wrong_inner = fixture(14)?;
    let participant = wrong_inner_body(&wrong_inner)?;
    let inner = InnerSupport::new(vec![DeviceParticipant::new(
        participant.device(),
        participant.node(),
        SharePoint::new(Point::from_scalar(Scalar::from(102_u64))?),
    )])?;
    let reservation = reservation_with_supports(&wrong_inner, inner, &wrong_inner.outer, 14)?;
    assert_eq!(
        wrong_inner
            .leaf
            .reserve(wrong_inner.session, 0, &reservation, &wrong_inner.outer),
        Err(Error::ShareMismatch)
    );
    assert_eq!(wrong_inner.leaf.next_sequence(), 0);

    let mut wrong_outer = fixture(15)?;
    let current = wrong_outer.outer.participants()[0];
    let outer = OuterSupport::new(vec![PersonParticipant::new(
        current.person(),
        current.slot(),
        Node::from_u64(2)?,
        current.member(),
    )])?;
    let inner = MemberReservation::from_bytes(&wrong_outer.reservation, &wrong_outer.outer)?
        .0
        .body()
        .inner_support()
        .clone();
    let reservation = reservation_with_supports(&wrong_outer, inner, &outer, 15)?;
    assert_eq!(
        wrong_outer
            .leaf
            .reserve(wrong_outer.session, 0, &reservation, &outer),
        Err(Error::ShareMismatch)
    );
    assert_eq!(wrong_outer.leaf.next_sequence(), 0);
    Ok(())
}

#[test]
fn authenticated_sibling_abort_closes_its_receiver() -> Result<()> {
    let mut valid = fixture(7)?;
    let attempt = valid
        .leaf
        .reserve(valid.session, 0, &valid.reservation, &valid.outer)?;
    valid.leaf.receive_abort(&AuthenticatedAbort::new(
        attempt,
        attempt,
        valid.session,
        &valid.reservation,
    ))?;
    assert_eq!(valid.leaf.stage(), None);
    assert!(valid.leaf.is_closed(attempt));

    let mut wrong_session = fixture(8)?;
    let wrong_attempt = wrong_session.leaf.reserve(
        wrong_session.session,
        0,
        &wrong_session.reservation,
        &wrong_session.outer,
    )?;
    assert_eq!(
        wrong_session.leaf.receive_abort(&AuthenticatedAbort::new(
            wrong_attempt,
            wrong_attempt,
            SessionId::new([0xff; 32]),
            &wrong_session.reservation,
        )),
        Err(Error::InvalidTranscript)
    );
    assert_eq!(wrong_session.leaf.stage(), Some(LeafStage::Reserved));
    assert!(!wrong_session.leaf.is_closed(wrong_attempt));
    wrong_session.leaf.close(wrong_attempt)?;
    Ok(())
}

#[test]
fn delivery_cannot_cross_leaf_attempts() -> Result<()> {
    let mut fixture = fixture(12)?;
    let first = fixture
        .leaf
        .reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?;
    fixture.leaf.close(first)?;
    let second = fixture
        .leaf
        .reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?;
    let mut rng = ChaCha20Rng::from_seed([12; 32]);
    let commitment = fixture
        .leaf
        .commit(second, &fixture.reservation, &mut rng)?;
    let stale = AuthenticatedCommitment::new(
        second,
        first,
        fixture.session,
        &fixture.reservation,
        commitment,
    );
    assert_eq!(
        fixture.leaf.reveal(second, vec![stale]),
        Err(Error::InvalidTranscript)
    );
    assert!(fixture.leaf.is_closed(second));
    Ok(())
}

#[test]
#[cfg(feature = "taproot")]
fn taproot_leaf_binds_the_output_before_nonce_creation() -> Result<()> {
    let mut wrong = taproot_fixture(8)?;
    let key = wrong.taproot_key.ok_or(Error::InvalidTranscript)?;
    let another = Key::new(wrong.prepackage.key(), Some([0x44; 32]))?.output_key();
    assert_ne!(key.output_key(), another);
    assert_eq!(
        wrong
            .leaf
            .reserve_taproot(wrong.session, 0, &wrong.reservation, another, &wrong.outer,),
        Err(Error::OutputKeyMismatch)
    );
    assert_eq!(wrong.leaf.next_sequence(), 0);

    let mut replay = taproot_fixture(9)?;
    let replay_key = replay.taproot_key.ok_or(Error::InvalidTranscript)?;
    let replay_attempt = replay.leaf.reserve_taproot(
        replay.session,
        0,
        &replay.reservation,
        replay_key.output_key(),
        &replay.outer,
    )?;
    assert_eq!(
        replay.leaf.reserve_taproot(
            replay.session,
            0,
            &replay.reservation,
            another,
            &replay.outer
        ),
        Err(Error::ReplayMismatch)
    );
    assert!(replay.leaf.is_closed(replay_attempt));

    let mut changed = taproot_fixture(10)?;
    let changed_key = changed.taproot_key.ok_or(Error::InvalidTranscript)?;
    let changed_attempt = changed.leaf.reserve_taproot(
        changed.session,
        0,
        &changed.reservation,
        changed_key.output_key(),
        &changed.outer,
    )?;
    let changed_nonce = complete_nonce_round(&mut changed, changed_attempt, [10; 32])?;
    let changed_root = RootPackage::finalize(
        changed.prepackage,
        &changed.outer,
        vec![MemberNonce::new(
            changed.outer.participants()[0].slot(),
            changed_nonce,
        )],
    )?;
    let other_key = Key::new(changed_root.key(), Some([0x45; 32]))?;
    let other_package = Package::new(changed_root, other_key)?;
    assert_eq!(
        changed
            .leaf
            .respond_taproot(changed_attempt, &other_package.to_bytes()?),
        Err(Error::InvalidTranscript)
    );
    assert!(changed.leaf.is_closed(changed_attempt));

    let mut valid = taproot_fixture(11)?;
    let valid_key = valid.taproot_key.ok_or(Error::InvalidTranscript)?;
    let valid_attempt = valid.leaf.reserve_taproot(
        valid.session,
        0,
        &valid.reservation,
        valid_key.output_key(),
        &valid.outer,
    )?;
    let nonce = complete_nonce_round(&mut valid, valid_attempt, [11; 32])?;
    let root = RootPackage::finalize(
        valid.prepackage,
        &valid.outer,
        vec![MemberNonce::new(
            valid.outer.participants()[0].slot(),
            nonce,
        )],
    )?;
    let package = Package::new(root, valid_key)?;
    let signing = package.signing()?;
    let response = valid
        .leaf
        .respond_taproot(valid_attempt, &package.to_bytes()?)?;
    let member =
        TaprootMemberResponse::new(valid.outer.participants()[0].slot(), response.scalar());
    let signature = signing.aggregate_signature(&valid.outer, &[member])?;
    signature.verify(valid_key.output_key(), package.sighash())?;
    assert!(valid.leaf.is_closed(valid_attempt));
    Ok(())
}

#[test]
#[cfg(feature = "taproot")]
fn taproot_reservation_cannot_answer_plain_profile() -> Result<()> {
    let mut converted = taproot_fixture(13)?;
    let converted_key = converted.taproot_key.ok_or(Error::InvalidTranscript)?;
    let converted_attempt = converted.leaf.reserve_taproot(
        converted.session,
        0,
        &converted.reservation,
        converted_key.output_key(),
        &converted.outer,
    )?;
    let converted_nonce = complete_nonce_round(&mut converted, converted_attempt, [13; 32])?;
    let plain_root = RootPackage::finalize(
        converted.prepackage,
        &converted.outer,
        vec![MemberNonce::new(
            converted.outer.participants()[0].slot(),
            converted_nonce,
        )],
    )?;
    assert_eq!(
        converted
            .leaf
            .respond(converted_attempt, &plain_root.to_bytes()?),
        Err(Error::ProtocolMismatch)
    );
    assert!(converted.leaf.is_closed(converted_attempt));
    Ok(())
}

struct Fixture {
    leaf: LeafRegistry,
    session: SessionId,
    reservation: zeroize::Zeroizing<Vec<u8>>,
    prepackage: RootPrepackage,
    outer: coupery_ksnf::support::OuterSupport,
    #[cfg(feature = "taproot")]
    taproot_key: Option<Key>,
}

fn fixture(marker: u8) -> Result<Fixture> {
    fixture_for(marker)
}

#[cfg(feature = "taproot")]
fn taproot_fixture(marker: u8) -> Result<Fixture> {
    fixture_for_taproot(marker)
}

fn fixture_for(marker: u8) -> Result<Fixture> {
    fixture_with_member(marker, false)
}

#[cfg(feature = "taproot")]
fn fixture_for_taproot(marker: u8) -> Result<Fixture> {
    fixture_with_member(marker, true)
}

fn fixture_with_member(marker: u8, taproot: bool) -> Result<Fixture> {
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
    let member =
        MemberReservation::new(prepackage.clone(), MemberOpening::new(salt, body), &outer)?;
    #[cfg(feature = "taproot")]
    let (reservation, taproot_key) = if taproot {
        let key = Key::new(prepackage.key(), None)?;
        (
            Reservation::new(member, key)?.to_bytes(session, 100)?,
            Some(key),
        )
    } else {
        (member.to_bytes(session, 100)?, None)
    };
    #[cfg(not(feature = "taproot"))]
    let reservation = {
        let _ = taproot;
        member.to_bytes(session, 100)?
    };
    Ok(Fixture {
        leaf: LeafRegistry::new(device_state, epoch)?,
        session,
        reservation,
        prepackage,
        outer,
        #[cfg(feature = "taproot")]
        taproot_key,
    })
}

#[cfg(feature = "taproot")]
fn complete_nonce_round(
    fixture: &mut Fixture,
    attempt: LeafAttempt,
    seed: [u8; 32],
) -> Result<NoncePair> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let commitment = fixture
        .leaf
        .commit(attempt, &fixture.reservation, &mut rng)?;
    let pair = fixture.leaf.reveal(
        attempt,
        vec![AuthenticatedCommitment::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            commitment,
        )],
    )?;
    fixture.leaf.fix(
        attempt,
        vec![AuthenticatedOpening::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            pair,
        )],
    )
}

fn wrong_inner_body(fixture: &Fixture) -> Result<coupery_ksnf::support::DeviceParticipant> {
    let reservation = MemberReservation::from_bytes(&fixture.reservation, &fixture.outer)?.0;
    reservation
        .body()
        .inner_support()
        .participants()
        .first()
        .copied()
        .ok_or(Error::ParticipantNotFound)
}

fn reservation_with_supports(
    fixture: &Fixture,
    inner: InnerSupport,
    outer: &OuterSupport,
    salt_marker: u8,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let current = MemberReservation::from_bytes(&fixture.reservation, &fixture.outer)?.0;
    let person = current.body().epoch().anchor().person();
    let body = MemberBody::new(
        current.body().identity(),
        current.body().member(),
        current.body().epoch(),
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(u64::from(salt_marker) + 70));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = RootPrepackage::new(
        fixture.prepackage.key(),
        fixture.prepackage.message().to_vec(),
        fixture.prepackage.context(),
        outer,
        vec![record],
    )?;
    MemberReservation::new(prepackage, MemberOpening::new(salt, body), outer)?
        .to_bytes(fixture.session, 100)
}

fn public_polynomial(constant: u64) -> Result<PublicPolynomial> {
    PublicPolynomial::new(vec![Element::from_scalar(Scalar::from(constant))])
}
