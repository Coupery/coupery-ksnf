#![allow(missing_docs)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::Result;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::{LeafRegistry, LeafStage};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::Signature;
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, RootContext,
    RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, SessionId, VaultId,
};

#[test]
fn receivers_fix_commitment_views_on_their_own_schedule() -> Result<()> {
    let mut fixture = fixture()?;
    fixture
        .leaf_1
        .reserve(fixture.session, &fixture.reservation, &fixture.outer)?;
    fixture
        .leaf_2
        .reserve(fixture.session, &fixture.reservation, &fixture.outer)?;
    let mut rng_1 = ChaCha20Rng::from_seed([1; 32]);
    let mut rng_2 = ChaCha20Rng::from_seed([2; 32]);
    let commitment_1 = fixture
        .leaf_1
        .commit(fixture.session, &fixture.reservation, &mut rng_1)?;
    let commitment_2 = fixture
        .leaf_2
        .commit(fixture.session, &fixture.reservation, &mut rng_2)?;

    let pair_1 = fixture.leaf_1.reveal(
        fixture.session,
        commitments(&fixture, fixture.device_1, commitment_1, commitment_2),
    )?;
    assert_eq!(fixture.leaf_1.stage(), Some(LeafStage::Held));
    assert_eq!(fixture.leaf_2.stage(), Some(LeafStage::Committed));

    let pair_2 = fixture.leaf_2.reveal(
        fixture.session,
        commitments(&fixture, fixture.device_2, commitment_1, commitment_2),
    )?;
    let aggregate_1 = fixture.leaf_1.fix(
        fixture.session,
        openings(&fixture, fixture.device_1, &pair_1, &pair_2),
    )?;
    let aggregate_2 = fixture.leaf_2.fix(
        fixture.session,
        openings(&fixture, fixture.device_2, &pair_1, &pair_2),
    )?;
    assert_eq!(aggregate_1, aggregate_2);

    let slot = fixture.outer.participants()[0].slot();
    let root = RootPackage::finalize(
        fixture.prepackage,
        &fixture.outer,
        vec![MemberNonce::new(slot, aggregate_1)],
    )?;
    let signing = SigningContext::new(&root)?;
    let root_bytes = root.to_bytes()?;
    let response_1 = fixture.leaf_1.respond(fixture.session, &root_bytes)?;
    let response_2 = fixture.leaf_2.respond(fixture.session, &root_bytes)?;
    Signature::new(signing.nonce(), response_1.scalar() + response_2.scalar())
        .verify(root.key(), root.message())?;
    Ok(())
}

struct Fixture {
    leaf_1: LeafRegistry,
    leaf_2: LeafRegistry,
    session: SessionId,
    reservation: zeroize::Zeroizing<Vec<u8>>,
    prepackage: RootPrepackage,
    outer: coupery_ksnf::support::OuterSupport,
    device_1: DeviceId,
    device_2: DeviceId,
}

fn fixture() -> Result<Fixture> {
    let vault = VaultId::new([0x51; 32]);
    let person = PersonId::new([0x61; 32]);
    let device_1 = DeviceId::new([0x71; 32]);
    let device_2 = DeviceId::new([0x72; 32]);
    let node_1 = Node::from_u64(1)?;
    let node_2 = Node::from_u64(2)?;
    let public_person = PublicPerson::new(
        person,
        node_1,
        public_polynomial(31, 3)?,
        public_polynomial(101, 7)?,
        vec![
            PublicDevice::new(device_1, node_1, share_point(34)?, share_point(108)?),
            PublicDevice::new(device_2, node_2, share_point(37)?, share_point(115)?),
        ],
    )?;
    let genesis =
        ValidatedPublicGenesis::from_parts(vault, public_polynomial(101, 0)?, vec![public_person])?;
    let outer = genesis.outer_support(&[person])?;
    let inner = genesis.inner_support(person, &[device_1, device_2])?;
    let state_1 = genesis.attach_share(
        person,
        device_1,
        SecretScalar::new(Scalar::from(34_u64)),
        SecretScalar::new(Scalar::from(108_u64)),
    )?;
    let state_2 = genesis.attach_share(
        person,
        device_2,
        SecretScalar::new(Scalar::from(37_u64)),
        SecretScalar::new(Scalar::from(115_u64)),
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
    let salt = SecretScalar::new(Scalar::from(41_u64));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        b"receiver schedule".to_vec(),
        RootContext::new(vault, epoch.outer(), CommandId::new([0x91; 32])),
        &outer,
        vec![record],
    )?;
    let session = SessionId::new([0xa1; 32]);
    let reservation =
        MemberReservation::new(prepackage.clone(), MemberOpening::new(salt, body), &outer)?
            .to_bytes(session, 100)?;
    Ok(Fixture {
        leaf_1: LeafRegistry::new(state_1, epoch)?,
        leaf_2: LeafRegistry::new(state_2, epoch)?,
        session,
        reservation,
        prepackage,
        outer,
        device_1,
        device_2,
    })
}

fn commitments(
    fixture: &Fixture,
    receiver: DeviceId,
    commitment_1: Scalar,
    commitment_2: Scalar,
) -> Vec<AuthenticatedCommitment> {
    vec![
        AuthenticatedCommitment::new(
            fixture.device_2,
            receiver,
            fixture.session,
            &fixture.reservation,
            commitment_2,
        ),
        AuthenticatedCommitment::new(
            fixture.device_1,
            receiver,
            fixture.session,
            &fixture.reservation,
            commitment_1,
        ),
    ]
}

fn openings(
    fixture: &Fixture,
    receiver: DeviceId,
    pair_1: &coupery_ksnf::signing::NoncePair,
    pair_2: &coupery_ksnf::signing::NoncePair,
) -> Vec<AuthenticatedOpening> {
    vec![
        AuthenticatedOpening::new(
            fixture.device_2,
            receiver,
            fixture.session,
            &fixture.reservation,
            *pair_2,
        ),
        AuthenticatedOpening::new(
            fixture.device_1,
            receiver,
            fixture.session,
            &fixture.reservation,
            *pair_1,
        ),
    ]
}

fn public_polynomial(constant: u64, linear: u64) -> Result<PublicPolynomial> {
    if linear == 0 {
        return PublicPolynomial::new(vec![Element::from_scalar(Scalar::from(constant))]);
    }
    PublicPolynomial::new(vec![
        Element::from_scalar(Scalar::from(constant)),
        Element::from_scalar(Scalar::from(linear)),
    ])
}

fn share_point(value: u64) -> Result<SharePoint> {
    Ok(SharePoint::new(Point::from_scalar(Scalar::from(value))?))
}
