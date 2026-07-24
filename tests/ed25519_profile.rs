//! Ed25519 profile interoperability tests.

#![cfg(feature = "ed25519")]

use ed25519_dalek::{Signature as DalekSignature, Verifier as _, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use sha2::{Digest as _, Sha256};

use coupery_ksnf::algebra::{Element, Point, ScalarFor, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::dealing::{
    Candidate, Command, Contribution, InstalledShare, RoleSpec, SingleShape, TargetAccumulator,
    TargetDevice, TargetShape,
};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
#[cfg(feature = "secp256k1")]
use coupery_ksnf::leaf::LeafMaterial;
use coupery_ksnf::leaf::{
    LeafRegistry, LeafStore as _, MemoryLeafStore, PersistError, PersistentLeaf,
};
use coupery_ksnf::log_act::{MemoryLog, Terminal};
use coupery_ksnf::profile::{Ed25519, Profile as _};
use coupery_ksnf::shamir::{Node, interpolate_constant};
use coupery_ksnf::signing::hazmat::respond_device;
use coupery_ksnf::signing::{
    DeviceNonce, DeviceNonceSet, DeviceResponse, Nonce, Signature, aggregate_member,
    aggregate_signature, challenge, verify_device,
};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, MemberTranscript,
    RootContext, RootEntry, RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, ScopeId,
    SessionId, Slot, VaultId,
};
use coupery_ksnf::{Error, Result};

type Scalar = ScalarFor<Ed25519>;

#[test]
fn webauthn_signature_survives_device_reshare() -> Result<()> {
    let key = VaultKey::<Ed25519>::new(Point::from_scalar(scalar(101))?);
    let message = assertion_message();
    let first_shares = [[scalar(127), scalar(136)], [scalar(158), scalar(181)]];

    let nodes = [[1, 2], [1, 2]];
    let first = sign_nested(key, &message, 1, nodes, first_shares)?;
    verify_independently(key, &message, first)?;

    let reshared = reshare_member(first_shares[0])?;
    let second = sign_nested(key, &message, 2, nodes, [reshared, first_shares[1]])?;
    verify_independently(key, &message, second)?;

    assert_eq!(key.to_bytes().len(), 32);
    assert_eq!(first.to_bytes().len(), 64);
    assert_ne!(first.to_bytes(), second.to_bytes());
    Ok(())
}

#[test]
fn mixed_inner_supports_sign() -> Result<()> {
    let key = VaultKey::<Ed25519>::new(Point::from_scalar(scalar(101))?);
    let message = assertion_message();
    let signature = sign_nested(
        key,
        &message,
        3,
        [[1, 3], [2, 3]],
        [[scalar(127), scalar(145)], [scalar(181), scalar(204)]],
    )?;
    verify_independently(key, &message, signature)
}

#[test]
fn persistent_leaf_never_releases_one_nonce_twice() -> Result<()> {
    let fixture = leaf_fixture()?;
    let mut store = MemoryLeafStore::<Ed25519>::default();
    let mut leaf = persist(PersistentLeaf::create(&mut store, fixture.leaf))?;
    let attempt = persist(leaf.reserve(
        &mut store,
        fixture.session,
        0,
        &fixture.reservation,
        &fixture.outer,
    ))?;
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let commitment = persist(leaf.commit(&mut store, attempt, &fixture.reservation, &mut rng))?;
    let pair = persist(leaf.reveal(
        &mut store,
        attempt,
        vec![AuthenticatedCommitment::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            commitment,
        )],
    ))?;
    persist(leaf.fix(
        &mut store,
        attempt,
        vec![AuthenticatedOpening::new(
            attempt,
            attempt,
            fixture.session,
            &fixture.reservation,
            pair,
        )],
    ))?;
    let root = RootPackage::finalize(
        fixture.prepackage,
        &fixture.outer,
        vec![MemberNonce::new(
            fixture.outer.participants()[0].slot(),
            pair,
        )],
    )?;
    let signing = SigningContext::new(&root)?;
    let response = persist(leaf.respond(&mut store, attempt, &root.to_bytes()?))?;
    let signature = Signature::new(signing.nonce(), response.scalar());
    verify_independently(root.key(), root.message(), signature)?;

    assert!(matches!(
        leaf.commit(&mut store, attempt, &fixture.reservation, &mut rng),
        Err(PersistError::Protocol(Error::AttemptClosed))
    ));
    let journal = store
        .journal(fixture.device)
        .ok_or(Error::ParticipantNotFound)?;
    assert!(journal.journal().is_closed(attempt));
    let material = store
        .get_material(journal.journal().material())?
        .ok_or(Error::ParticipantNotFound)?;
    assert_eq!(&material.as_bytes()[..8], b"KSNFE1M1");
    Ok(())
}

#[test]
fn ed25519_altered_transcript_closes_the_attempt() -> Result<()> {
    let fixture = leaf_fixture()?;
    let mut store = MemoryLeafStore::<Ed25519>::default();
    let mut leaf = persist(PersistentLeaf::create(&mut store, fixture.leaf))?;
    let attempt = persist(leaf.reserve(
        &mut store,
        fixture.session,
        0,
        &fixture.reservation,
        &fixture.outer,
    ))?;
    let mut rng = ChaCha20Rng::from_seed([0x78; 32]);
    persist(leaf.commit(&mut store, attempt, &fixture.reservation, &mut rng))?;

    let mut altered = fixture.reservation.clone();
    altered[0] ^= 1;
    assert!(matches!(
        leaf.commit(&mut store, attempt, &altered, &mut rng),
        Err(PersistError::Protocol(Error::ReplayMismatch))
    ));
    let journal = store
        .journal(fixture.device)
        .ok_or(Error::ParticipantNotFound)?;
    assert!(journal.journal().is_closed(attempt));
    Ok(())
}

#[test]
fn ed25519_decoding_rejects_unsafe_inputs() {
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert_eq!(
        Point::<Ed25519>::from_bytes(&identity),
        Err(Error::IdentityPoint)
    );

    let mut order_two = [0xff_u8; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    assert_eq!(
        Point::<Ed25519>::from_bytes(&order_two),
        Err(Error::InvalidPoint)
    );

    let mut noncanonical = [0xff_u8; 32];
    noncanonical[0] = 0xed;
    noncanonical[31] = 0x7f;
    assert!(Point::<Ed25519>::from_bytes(&noncanonical).is_err());
    assert!(Point::<Ed25519>::from_bytes(&[0xff; 32]).is_err());

    let attempt = LeafAttempt::new(DeviceId::new([0xc1; 32]), 1);
    let mut response = DeviceResponse::<Ed25519>::new(attempt, scalar(7)).to_bytes();
    response[41..].fill(0xff);
    assert_eq!(
        DeviceResponse::<Ed25519>::from_bytes(&response),
        Err(Error::InvalidScalar)
    );
}

#[test]
fn ed25519_rejects_altered_responses() -> Result<()> {
    let share = SecretScalar::new(scalar(17));
    let nonce = Nonce::<Ed25519>::new(scalar(3), scalar(5))?;
    let pair = nonce.commitments()?;
    let binding = scalar(7);
    let challenge_scalar = scalar(11);
    let coefficient = scalar(13);
    let response = nonce.respond(binding, challenge_scalar, coefficient, &share);
    let public = SharePoint::new(Element::from_scalar(scalar(17)));
    verify_device(
        response,
        pair,
        binding,
        challenge_scalar,
        coefficient,
        public,
    )?;
    assert_eq!(
        verify_device(
            response + scalar(1),
            pair,
            binding,
            challenge_scalar,
            coefficient,
            public,
        ),
        Err(Error::InvalidPartial)
    );

    let key = VaultKey::<Ed25519>::new(Point::from_scalar(scalar(101))?);
    let message = b"exact assertion bytes";
    let nonce = Point::from_scalar(scalar(19))?;
    let response = scalar(19) + challenge::<Ed25519>(nonce, key, message)? * scalar(101);
    let signature = Signature::new(nonce, response);
    signature.verify(key, message)?;
    assert_eq!(
        Signature::new(nonce, response + scalar(1)).verify(key, message),
        Err(Error::InvalidSignature)
    );
    Ok(())
}

#[cfg(feature = "secp256k1")]
#[test]
fn structured_inputs_cannot_cross_profiles() -> Result<()> {
    use coupery_ksnf::profile::Secp256k1;

    let attempt = LeafAttempt::new(DeviceId::new([0xc2; 32]), 2);
    let ed = DeviceResponse::<Ed25519>::new(attempt, scalar(7)).to_bytes();
    let secp =
        DeviceResponse::<Secp256k1>::new(attempt, coupery_ksnf::algebra::Scalar::from(7_u64))
            .to_bytes();
    assert_eq!(
        DeviceResponse::<Ed25519>::from_bytes(&secp),
        Err(Error::UnsupportedVersion)
    );
    assert_eq!(
        DeviceResponse::<Secp256k1>::from_bytes(&ed),
        Err(Error::UnsupportedVersion)
    );

    let fixture = leaf_fixture()?;
    let mut store = MemoryLeafStore::<Ed25519>::default();
    let _leaf = persist(PersistentLeaf::create(&mut store, fixture.leaf))?;
    let journal = store
        .journal(fixture.device)
        .ok_or(Error::ParticipantNotFound)?;
    let material = store
        .get_material(journal.journal().material())?
        .ok_or(Error::ParticipantNotFound)?;
    assert!(matches!(
        LeafMaterial::<Secp256k1>::from_bytes(material.as_bytes().to_vec()),
        Err(Error::ProtocolMismatch)
    ));
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "Keeps the nested signing path intact."
)]
fn sign_nested(
    key: VaultKey<Ed25519>,
    message: &[u8],
    generation: u8,
    nodes_by_person: [[u64; 2]; 2],
    shares_by_person: [[Scalar; 2]; 2],
) -> Result<Signature<Ed25519>> {
    let vault = VaultId::new([0x55; 32]);
    let people = [PersonId::new([0xa1; 32]), PersonId::new([0xa2; 32])];
    let member_scalars = [scalar(118), scalar(135)];
    let members = [
        MemberPoint::new(Point::from_scalar(member_scalars[0])?),
        MemberPoint::new(Point::from_scalar(member_scalars[1])?),
    ];
    let outer = OuterSupport::new(vec![
        PersonParticipant::new(people[0], Slot::new(1), Node::from_u64(1)?, members[0]),
        PersonParticipant::new(people[1], Slot::new(2), Node::from_u64(2)?, members[1]),
    ])?;

    let mut bodies = Vec::new();
    let mut salts = Vec::new();
    let mut nonce_sets = Vec::new();
    let mut nonces = Vec::new();
    let mut device_ids = Vec::new();
    let mut shares = Vec::new();

    for index in 0..2 {
        let person_index = u8::try_from(index + 1).map_err(|_| Error::LengthOverflow)?;
        let devices = [
            DeviceId::new([generation * 0x20 + person_index * 2; 32]),
            DeviceId::new([generation * 0x20 + person_index * 2 + 1; 32]),
        ];
        let device_shares = shares_by_person[index];
        let inner = InnerSupport::new(vec![
            DeviceParticipant::new(
                devices[0],
                Node::from_u64(nodes_by_person[index][0])?,
                SharePoint::new(Element::from_scalar(device_shares[0])),
            ),
            DeviceParticipant::new(
                devices[1],
                Node::from_u64(nodes_by_person[index][1])?,
                SharePoint::new(Element::from_scalar(device_shares[1])),
            ),
        ])?;
        let body = MemberBody::new(
            IdentityKey::new(Point::from_scalar(scalar(31 + 6 * index as u64))?),
            members[index],
            KeyEpoch::new(
                OuterEpoch::new(7),
                InnerEpoch::new(u64::from(generation)),
                AnchorId::new(
                    vault,
                    people[index],
                    ActivationHandle::new([0x80 + generation; 32]),
                    ActivationHandle::new([0x90 + generation; 32]),
                ),
            ),
            inner.clone(),
            outer.coefficient(people[index])?,
        )?;
        let salt = SecretScalar::new(scalar(70 + index as u64 + u64::from(generation)));
        let pair = [
            Nonce::new(
                scalar(101 + 20 * index as u64 + u64::from(generation)),
                scalar(102 + 20 * index as u64 + u64::from(generation)),
            )?,
            Nonce::new(
                scalar(103 + 20 * index as u64 + u64::from(generation)),
                scalar(104 + 20 * index as u64 + u64::from(generation)),
            )?,
        ];
        let nonce_set = DeviceNonceSet::new(
            &inner,
            vec![
                DeviceNonce::new(
                    LeafAttempt::new(devices[0], u64::from(generation)),
                    pair[0].commitments()?,
                ),
                DeviceNonce::new(
                    LeafAttempt::new(devices[1], u64::from(generation)),
                    pair[1].commitments()?,
                ),
            ],
        )?;
        bodies.push(body);
        salts.push(salt);
        nonce_sets.push(nonce_set);
        nonces.push(pair.into_iter().collect::<Vec<_>>());
        device_ids.push(devices);
        shares.push(device_shares);
    }

    let records = bodies
        .iter()
        .zip(&salts)
        .map(|(body, salt)| MemberRecord::commit(body, salt))
        .collect::<Result<Vec<_>>>()?;
    let root = RootPackage::new(
        key,
        message.to_vec(),
        RootContext::new(
            vault,
            OuterEpoch::new(7),
            CommandId::new([0x60 + generation; 32]),
        ),
        &outer,
        vec![
            RootEntry::new(records[0], nonce_sets[0].aggregate()),
            RootEntry::new(records[1], nonce_sets[1].aggregate()),
        ],
    )?;
    let signing = SigningContext::new(&root)?;
    let mut member_responses = Vec::new();

    for index in 0..2 {
        let transcript = MemberTranscript::new(
            root.clone(),
            MemberOpening::new(
                SecretScalar::new(scalar(70 + index as u64 + u64::from(generation))),
                bodies[index].clone(),
            ),
            &outer,
        )?;
        let responses = [
            respond_device(
                nonces[index].remove(0),
                &transcript,
                &signing,
                &nonce_sets[index],
                device_ids[index][0],
                &SecretScalar::new(shares[index][0]),
            )?,
            respond_device(
                nonces[index].remove(0),
                &transcript,
                &signing,
                &nonce_sets[index],
                device_ids[index][1],
                &SecretScalar::new(shares[index][1]),
            )?,
        ];
        member_responses.push(aggregate_member(
            &transcript,
            &signing,
            &nonce_sets[index],
            &responses,
        )?);
    }
    aggregate_signature(&signing, &outer, &member_responses)
}

fn assertion_message() -> Vec<u8> {
    let authenticator_data = [0xa5; 37];
    let client_data_hash = Sha256::digest(
        br#"{"type":"webauthn.get","challenge":"c","origin":"https://coupery.com"}"#,
    );
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(&authenticator_data);
    message.extend_from_slice(&client_data_hash);
    message
}

fn verify_independently(
    key: VaultKey<Ed25519>,
    message: &[u8],
    signature: Signature<Ed25519>,
) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(&key.to_bytes()).map_err(|_| Error::InvalidPoint)?;
    let signature = DalekSignature::from_bytes(&signature.to_bytes());
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| Error::InvalidSignature)
}

fn reshare_member(source_shares: [Scalar; 2]) -> Result<[Scalar; 2]> {
    let source_devices = [DeviceId::new([0x11; 32]), DeviceId::new([0x12; 32])];
    let target_devices = [DeviceId::new([0x41; 32]), DeviceId::new([0x42; 32])];
    let source = InnerSupport::new(vec![
        DeviceParticipant::new(
            source_devices[0],
            Node::from_u64(1)?,
            SharePoint::new(Element::from_scalar(source_shares[0])),
        ),
        DeviceParticipant::new(
            source_devices[1],
            Node::from_u64(2)?,
            SharePoint::new(Element::from_scalar(source_shares[1])),
        ),
    ])?;
    let shape = TargetShape::Single(SingleShape::new(
        2,
        vec![
            TargetDevice::new(target_devices[0], Node::from_u64(1)?),
            TargetDevice::new(target_devices[1], Node::from_u64(2)?),
        ],
    )?);
    let roles = vec![
        RoleSpec::source(
            source_devices[0],
            SharePoint::new(Element::from_scalar(source_shares[0])),
            source.source_weight(source_devices[0])?,
        )?,
        RoleSpec::source(
            source_devices[1],
            SharePoint::new(Element::from_scalar(source_shares[1])),
            source.source_weight(source_devices[1])?,
        )?,
        RoleSpec::refresher(target_devices[0]),
        RoleSpec::refresher(target_devices[1]),
    ];
    let scope = ScopeId::new([0x51; 32]);
    let predecessor = ActivationHandle::new([0x52; 32]);
    let command = Command::new(
        scope,
        CommandId::new([0x53; 32]),
        predecessor,
        Point::from_scalar(scalar(118))?,
        shape,
        roles,
    )?;
    let mut rng = ChaCha20Rng::from_seed([0x54; 32]);
    let contributions = vec![
        Contribution::source(
            &command,
            source_devices[0],
            &SecretScalar::new(source_shares[0]),
            &mut rng,
        )?,
        Contribution::source(
            &command,
            source_devices[1],
            &SecretScalar::new(source_shares[1]),
            &mut rng,
        )?,
        Contribution::refresher(&command, target_devices[0], &mut rng)?,
        Contribution::refresher(&command, target_devices[1], &mut rng)?,
    ];
    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;
    let installed = execute_reshare(&command, &contributions, &mut log)?;
    let shares = [
        installed[0].expose(|share| *share),
        installed[1].expose(|share| *share),
    ];
    assert_eq!(
        interpolate_constant::<Ed25519>(&[Node::from_u64(1)?, Node::from_u64(2)?], &shares,)?,
        scalar(118)
    );
    Ok(shares)
}

fn execute_reshare(
    command: &Command<Ed25519>,
    contributions: &[Contribution<Ed25519>],
    log: &mut MemoryLog,
) -> Result<Vec<InstalledShare<Ed25519>>> {
    let mut candidate = Candidate::new(command.clone(), log)?;
    for contribution in contributions {
        candidate.commit(contribution.role(), contribution.commitment(), log)?;
    }
    candidate.close_commitments(log)?;
    let mut released = Vec::with_capacity(contributions.len());
    for contribution in contributions {
        released.push(candidate.open_contribution(contribution, log)?);
    }
    let view = candidate.close_openings(log)?;
    let mut pending = Vec::new();
    for target in command.shape().targets() {
        let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
        for contribution in &released {
            accumulator.receive(contribution.share(command, target)?)?;
        }
        let (receipt, share) = accumulator.finish()?.into_parts();
        candidate.receipt(receipt, log)?;
        pending.push(share);
    }
    let terminal = candidate.activate(log)?;
    let Terminal::Activated(_) = terminal else {
        return Err(Error::InvalidTranscript);
    };
    pending
        .into_iter()
        .map(|share| share.resolve(terminal)?.ok_or(Error::InvalidTranscript))
        .collect()
}

fn scalar(value: u64) -> Scalar {
    Ed25519::scalar_from_u64(value)
}

struct LeafFixture {
    leaf: LeafRegistry<Ed25519>,
    outer: OuterSupport<Ed25519>,
    prepackage: RootPrepackage<Ed25519>,
    reservation: zeroize::Zeroizing<Vec<u8>>,
    session: SessionId,
    device: DeviceId,
}

fn leaf_fixture() -> Result<LeafFixture> {
    let vault = VaultId::new([0xb1; 32]);
    let person = PersonId::new([0xb2; 32]);
    let device = DeviceId::new([0xb3; 32]);
    let node = Node::from_u64(1)?;
    let identity = scalar(31);
    let member = scalar(101);
    let public_person = PublicPerson::new(
        person,
        node,
        public_polynomial(identity)?,
        public_polynomial(member)?,
        vec![PublicDevice::new(
            device,
            node,
            SharePoint::new(Element::from_scalar(identity)),
            SharePoint::new(Element::from_scalar(member)),
        )],
    )?;
    let genesis =
        ValidatedPublicGenesis::validate(vault, public_polynomial(member)?, vec![public_person])?;
    let outer = genesis.outer_support(&[person])?;
    let inner = genesis.inner_support(person, &[device])?;
    let epoch = KeyEpoch::new(
        OuterEpoch::new(1),
        InnerEpoch::new(1),
        AnchorId::new(
            vault,
            person,
            ActivationHandle::new([0xb4; 32]),
            ActivationHandle::new([0xb5; 32]),
        ),
    );
    let body = MemberBody::new(
        genesis.person(person)?.identity_key(),
        genesis.person(person)?.member_point(),
        epoch,
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(scalar(41));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        assertion_message(),
        RootContext::new(vault, epoch.outer(), CommandId::new([0xb6; 32])),
        &outer,
        vec![record],
    )?;
    let session = SessionId::new([0xb7; 32]);
    let reservation =
        MemberReservation::new(prepackage.clone(), MemberOpening::new(salt, body), &outer)?
            .to_bytes(session, 100)?;
    let genesis = genesis.attach_share(
        person,
        device,
        SecretScalar::new(identity),
        SecretScalar::new(member),
    )?;
    Ok(LeafFixture {
        leaf: LeafRegistry::new(genesis, epoch)?,
        outer,
        prepackage,
        reservation,
        session,
        device,
    })
}

fn public_polynomial(constant: Scalar) -> Result<PublicPolynomial<Ed25519>> {
    PublicPolynomial::new(vec![Element::from_scalar(constant)])
}

fn persist<T>(result: core::result::Result<T, PersistError<Error>>) -> Result<T> {
    result.map_err(|error| match error {
        PersistError::Protocol(error)
        | PersistError::InvalidRecord(error)
        | PersistError::Store(error) => error,
        _ => Error::InvalidTranscript,
    })
}
