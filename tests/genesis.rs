#![allow(missing_docs)]

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::SharePoint;
use coupery_ksnf::shamir::Node;
use coupery_ksnf::types::{DeviceId, PersonId, VaultId};
use coupery_ksnf::{Error, Result};

#[test]
fn genesis_checks_public_polynomials_and_attached_shares() -> Result<()> {
    let vault = VaultId::new([0x55; 32]);
    let person_1 = PersonId::new([0xa1; 32]);
    let person_2 = PersonId::new([0xa2; 32]);
    let device_11 = DeviceId::new([0x11; 32]);
    let device_12 = DeviceId::new([0x12; 32]);
    let device_21 = DeviceId::new([0x21; 32]);
    let device_22 = DeviceId::new([0x22; 32]);

    let public_person_1 = public_person(
        person_1,
        1,
        (31, 3),
        (118, 9),
        [(device_11, 1), (device_12, 2)],
    )?;
    let public_person_2 = public_person(
        person_2,
        2,
        (37, 5),
        (135, 11),
        [(device_21, 1), (device_22, 2)],
    )?;
    let people = vec![public_person_2, public_person_1];
    let genesis =
        ValidatedPublicGenesis::from_parts(vault, public_polynomial(101, 17)?, people.clone())?;

    let outer = genesis.outer_support(&[person_2, person_1])?;
    assert_eq!(outer.participants()[0].person(), person_1);
    assert_eq!(outer.coefficient(person_1)?.scalar(), Scalar::from(2_u64));
    let inner = genesis.inner_support(person_1, &[device_12, device_11])?;
    assert_eq!(inner.participants()[0].device(), device_11);

    let attached = genesis.attach_share(
        person_1,
        device_11,
        SecretScalar::new(Scalar::from(34_u64)),
        SecretScalar::new(Scalar::from(127_u64)),
    )?;
    attached
        .signing_share()
        .expose(|share| assert_eq!(*share, Scalar::from(127_u64)));
    attached.with_anchor(|share| assert_eq!(*share, Scalar::from(93_u64)));
    assert_eq!(attached.device(), device_11);

    assert_eq!(
        genesis
            .attach_share(
                person_1,
                device_11,
                SecretScalar::new(Scalar::from(34_u64)),
                SecretScalar::new(Scalar::from(128_u64)),
            )
            .err(),
        Some(Error::ShareMismatch)
    );
    assert_eq!(
        ValidatedPublicGenesis::from_parts(vault, public_polynomial(101, 18)?, people).err(),
        Some(Error::ShareMismatch)
    );
    Ok(())
}

fn public_person(
    person: PersonId,
    outer_node: u64,
    identity: (u64, u64),
    member: (u64, u64),
    devices: [(DeviceId, u64); 2],
) -> Result<PublicPerson> {
    let public_devices = devices
        .into_iter()
        .map(|(device, node)| {
            let identity_share = identity.0 + identity.1 * node;
            let member_share = member.0 + member.1 * node;
            Ok(PublicDevice::new(
                device,
                Node::from_u64(node)?,
                SharePoint::new(Point::from_scalar(Scalar::from(identity_share))?),
                SharePoint::new(Point::from_scalar(Scalar::from(member_share))?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    PublicPerson::new(
        person,
        Node::from_u64(outer_node)?,
        public_polynomial(identity.0, identity.1)?,
        public_polynomial(member.0, member.1)?,
        public_devices,
    )
}

fn public_polynomial(constant: u64, linear: u64) -> Result<PublicPolynomial> {
    PublicPolynomial::new(vec![
        Element::from_scalar(Scalar::from(constant)),
        Element::from_scalar(Scalar::from(linear)),
    ])
}
