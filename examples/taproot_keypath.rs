//! Signs a Taproot key path through the persistent leaf driver.

use k256::schnorr::{Signature as K256Signature, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::MemoryLeafStore;
use coupery_ksnf::secp256k1::{LeafRegistry, PersistentLeaf, ValidatedPublicGenesis};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::support::OuterSupport;
use coupery_ksnf::taproot::{Key, MemberResponse, Package, Reservation};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, RootContext,
    RootPackage, RootPrepackage,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, SessionId, VaultId,
};

type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const NOW: u64 = 50;
const EXPIRY: u64 = 100;

struct Fixture {
    genesis: ValidatedPublicGenesis,
    outer: OuterSupport,
    epoch: KeyEpoch,
    prepackage: RootPrepackage,
    reservation: zeroize::Zeroizing<Vec<u8>>,
    key: Key,
    session: SessionId,
    person: PersonId,
    device: DeviceId,
    identity: Scalar,
    member: Scalar,
    sighash: [u8; 32],
}

fn fixture() -> coupery_ksnf::Result<Fixture> {
    let vault = VaultId::new([0x51; 32]);
    let person = PersonId::new([0x61; 32]);
    let device = DeviceId::new([0x71; 32]);
    let node = Node::from_u64(1)?;
    let identity = Scalar::from(31_u64);
    let member = Scalar::from(101_u64);
    let genesis = ValidatedPublicGenesis::validate(
        vault,
        polynomial(member)?,
        vec![PublicPerson::new(
            person,
            node,
            polynomial(identity)?,
            polynomial(member)?,
            vec![PublicDevice::new(
                device,
                node,
                SharePoint::new(Element::from_scalar(identity)),
                SharePoint::new(Element::from_scalar(member)),
            )],
        )?],
    )?;
    let outer = genesis.outer_support(&[person])?;
    let inner = genesis.inner_support(person, &[device])?;
    let epoch = KeyEpoch::new(
        OuterEpoch::new(1),
        InnerEpoch::new(1),
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
    let salt = Scalar::from(41_u64);
    let record = MemberRecord::commit(&body, &SecretScalar::new(salt))?;
    let sighash = [0x42; 32];
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        sighash.to_vec(),
        RootContext::new(vault, epoch.outer(), CommandId::new([0x66; 32])),
        &outer,
        vec![record],
    )?;
    let member_reservation = MemberReservation::new(
        prepackage.clone(),
        MemberOpening::new(SecretScalar::new(salt), body),
        &outer,
    )?;
    let key = Key::new(genesis.vault_key(), Some([0x5a; 32]))?;
    let session = SessionId::new([0x77; 32]);
    let reservation = Reservation::new(member_reservation, key)?.to_bytes(session, EXPIRY)?;
    Ok(Fixture {
        genesis,
        outer,
        epoch,
        prepackage,
        reservation,
        key,
        session,
        person,
        device,
        identity,
        member,
        sighash,
    })
}

fn main() -> AnyResult<()> {
    let fixture = fixture()?;
    let device_state = fixture.genesis.attach_share(
        fixture.person,
        fixture.device,
        SecretScalar::new(fixture.identity),
        SecretScalar::new(fixture.member),
    )?;
    let mut store = MemoryLeafStore::default();
    let mut leaf =
        PersistentLeaf::create(&mut store, LeafRegistry::new(device_state, fixture.epoch)?)?;
    let attempt = leaf.reserve_taproot(
        &mut store,
        fixture.session,
        NOW,
        &fixture.reservation,
        fixture.key.output_key(),
        &fixture.outer,
    )?;
    let commitment = leaf.commit(
        &mut store,
        attempt,
        &fixture.reservation,
        &mut ChaCha20Rng::from_seed([1; 32]),
    )?;
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
    let package = Package::new(root, fixture.key)?;
    let signing = package.signing()?;
    let response = leaf.respond_taproot(&mut store, attempt, &package.to_bytes()?)?;
    let member = MemberResponse::new(fixture.outer.participants()[0].slot(), response.scalar());
    let signature = signing.aggregate_signature(&fixture.outer, &[member])?;

    signature.verify(fixture.key.output_key(), package.sighash())?;
    let verifier = VerifyingKey::from_bytes(&fixture.key.output_key().to_bytes())
        .map_err(|_| coupery_ksnf::Error::InvalidPoint)?;
    let parsed = K256Signature::try_from(signature.to_bytes().as_slice())
        .map_err(|_| coupery_ksnf::Error::InvalidSignature)?;
    assert!(verifier.verify_raw(&fixture.sighash, &parsed).is_ok());
    assert!(leaf.state().is_some_and(|state| state.is_closed(attempt)));
    Ok(())
}

fn polynomial(constant: Scalar) -> coupery_ksnf::Result<PublicPolynomial> {
    PublicPolynomial::new(vec![Element::from_scalar(constant)])
}
