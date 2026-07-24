use coupery_ksnf::algebra::{Element, Point, ScalarFor, SecretScalar};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint, VaultKey};
use coupery_ksnf::profile::Profile;
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::hazmat::respond_device;
use coupery_ksnf::signing::{
    DeviceNonce, DeviceNonceSet, Nonce, NoncePair, Signature, aggregate_member, aggregate_signature,
};
use coupery_ksnf::support::OuterSupport;
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberTranscript, RootContext, RootEntry, RootPackage,
    SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, VaultId,
};
use coupery_ksnf::{Error, Result};

pub struct Session<P: Profile> {
    pub vault_key: VaultKey<P>,
    pub outer: OuterSupport<P>,
    pub root: RootPackage<P>,
    pub message: Vec<u8>,
    people: Vec<Person<P>>,
}

struct Person<P: Profile> {
    transcript: MemberTranscript<P>,
    nonces: DeviceNonceSet<P>,
    devices: Vec<Device<P>>,
}

struct Device<P: Profile> {
    id: DeviceId,
    share: ScalarFor<P>,
    hiding: ScalarFor<P>,
    binding: ScalarFor<P>,
}

struct PersonAssembly<P: Profile> {
    body: MemberBody<P>,
    salt: SecretScalar<P>,
    record: MemberRecord<P>,
    nonces: DeviceNonceSet<P>,
    devices: Vec<Device<P>>,
}

pub fn two_of_three<P: Profile>(message: impl Into<Vec<u8>>) -> Result<Session<P>> {
    let message = message.into();
    let vault = VaultId::new([0x55; 32]);
    let outer_epoch = OuterEpoch::new(7);
    let genesis = genesis::<P>(vault)?;
    let vault_key = genesis.vault_key();
    let selected = [(1_u8, [1_u64, 3_u64]), (3_u8, [2_u64, 3_u64])];
    let outer = genesis.outer_support(
        &selected
            .iter()
            .map(|(person, _)| person_id(*person))
            .collect::<Vec<_>>(),
    )?;

    let mut assemblies = Vec::new();
    for (person, nodes) in selected {
        assemblies.push(assemble_person(
            &genesis,
            vault,
            outer_epoch,
            &outer,
            person,
            nodes,
        )?);
    }
    let entries = assemblies
        .iter()
        .map(|person| RootEntry::new(person.record, person.nonces.aggregate()))
        .collect();
    let root = RootPackage::new(
        vault_key,
        message.clone(),
        RootContext::new(vault, outer_epoch, CommandId::new([0x66; 32])),
        &outer,
        entries,
    )?;

    let mut people = Vec::new();
    for person in assemblies {
        let transcript = MemberTranscript::new(
            root.clone(),
            MemberOpening::new(person.salt, person.body),
            &outer,
        )?;
        people.push(Person {
            transcript,
            nonces: person.nonces,
            devices: person.devices,
        });
    }
    Ok(Session {
        vault_key,
        outer,
        root,
        message,
        people,
    })
}

pub fn sign_plain<P: Profile>(session: &Session<P>) -> Result<Signature<P>> {
    let signing = SigningContext::new(&session.root)?;
    let mut members = Vec::new();
    for person in &session.people {
        let mut devices = Vec::new();
        for device in &person.devices {
            devices.push(respond_device(
                Nonce::new(device.hiding, device.binding)?,
                &person.transcript,
                &signing,
                &person.nonces,
                device.id,
                &SecretScalar::new(device.share),
            )?);
        }
        members.push(aggregate_member(
            &person.transcript,
            &signing,
            &person.nonces,
            &devices,
        )?);
    }
    aggregate_signature(&signing, &session.outer, &members)
}

fn assemble_person<P: Profile>(
    genesis: &ValidatedPublicGenesis<P>,
    vault: VaultId,
    outer_epoch: OuterEpoch,
    outer: &OuterSupport<P>,
    index: u8,
    nodes: [u64; 2],
) -> Result<PersonAssembly<P>> {
    let person = person_id(index);
    let mut devices = Vec::new();
    let mut selected_devices = Vec::new();
    let mut nonces = Vec::new();
    for (position, node) in nodes.into_iter().enumerate() {
        let position = u64::try_from(position).map_err(|_| Error::LengthOverflow)?;
        let device = device_id(
            index,
            u8::try_from(node).map_err(|_| Error::LengthOverflow)?,
        );
        let share = member_share::<P>(index, node);
        let hiding = scalar::<P>(10 + u64::from(index) * 10 + position * 4 + 1);
        let binding = scalar::<P>(10 + u64::from(index) * 10 + position * 4 + 2);
        let pair = NoncePair::new(Point::from_scalar(hiding)?, Point::from_scalar(binding)?);
        selected_devices.push(device);
        nonces.push(DeviceNonce::new(LeafAttempt::new(device, node), pair));
        devices.push(Device {
            id: device,
            share,
            hiding,
            binding,
        });
    }
    let inner = genesis.inner_support(person, &selected_devices)?;
    let nonces = DeviceNonceSet::new(&inner, nonces)?;
    let body = MemberBody::new(
        genesis.person(person)?.identity_key(),
        genesis.person(person)?.member_point(),
        KeyEpoch::new(
            outer_epoch,
            InnerEpoch::new(10 + u64::from(index)),
            AnchorId::new(
                vault,
                person,
                ActivationHandle::new([0x80 + index; 32]),
                ActivationHandle::new([0x90 + index; 32]),
            ),
        ),
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(scalar::<P>(70 + u64::from(index)));
    let record = MemberRecord::commit(&body, &salt)?;
    Ok(PersonAssembly {
        body,
        salt,
        record,
        nonces,
        devices,
    })
}

fn genesis<P: Profile>(vault: VaultId) -> Result<ValidatedPublicGenesis<P>> {
    let mut people = Vec::new();
    for index in 1..=3 {
        let mut devices = Vec::new();
        for node in 1..=3 {
            devices.push(PublicDevice::new(
                device_id(index, node),
                Node::from_u64(u64::from(node))?,
                SharePoint::new(Element::from_scalar(identity_share::<P>(
                    index,
                    u64::from(node),
                ))),
                SharePoint::new(Element::from_scalar(member_share::<P>(
                    index,
                    u64::from(node),
                ))),
            ));
        }
        people.push(PublicPerson::new(
            person_id(index),
            Node::from_u64(u64::from(index))?,
            polynomial(&[identity_constant::<P>(index), identity_slope::<P>(index)])?,
            polynomial(&[outer_share::<P>(index), member_slope::<P>(index)])?,
            devices,
        )?);
    }
    ValidatedPublicGenesis::validate(
        vault,
        polynomial(&[scalar::<P>(101), scalar::<P>(17)])?,
        people,
    )
}

fn polynomial<P: Profile>(coefficients: &[ScalarFor<P>]) -> Result<PublicPolynomial<P>> {
    PublicPolynomial::new(
        coefficients
            .iter()
            .map(|coefficient| Element::from_scalar(*coefficient))
            .collect(),
    )
}

fn identity_constant<P: Profile>(index: u8) -> ScalarFor<P> {
    scalar::<P>(match index {
        1 => 31,
        2 => 37,
        _ => 41,
    })
}

fn identity_slope<P: Profile>(index: u8) -> ScalarFor<P> {
    scalar::<P>(match index {
        1 => 3,
        2 => 5,
        _ => 7,
    })
}

fn member_slope<P: Profile>(index: u8) -> ScalarFor<P> {
    scalar::<P>(match index {
        1 => 9,
        2 => 11,
        _ => 13,
    })
}

fn outer_share<P: Profile>(index: u8) -> ScalarFor<P> {
    scalar::<P>(101) + scalar::<P>(17) * scalar::<P>(u64::from(index))
}

fn member_share<P: Profile>(index: u8, node: u64) -> ScalarFor<P> {
    outer_share::<P>(index) + member_slope::<P>(index) * scalar::<P>(node)
}

fn identity_share<P: Profile>(index: u8, node: u64) -> ScalarFor<P> {
    identity_constant::<P>(index) + identity_slope::<P>(index) * scalar::<P>(node)
}

fn scalar<P: Profile>(value: u64) -> ScalarFor<P> {
    P::scalar_from_u64(value)
}

const fn person_id(index: u8) -> PersonId {
    PersonId::new([0xa0 + index; 32])
}

const fn device_id(person: u8, node: u8) -> DeviceId {
    DeviceId::new([person * 0x10 + node; 32])
}
