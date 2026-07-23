#![allow(missing_docs)]

use coupery_ksnf::Error;
use coupery_ksnf::algebra::{Point, Scalar};
use coupery_ksnf::keys::{MemberPoint, SharePoint};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::types::{DeviceId, PersonId, Slot};

#[test]
fn supports_sort_and_derive_coefficients() -> Result<(), Error> {
    let device_a = DeviceId::new([1; 32]);
    let device_b = DeviceId::new([2; 32]);
    let share_a = SharePoint::new(Point::from_scalar(Scalar::from(13_u64))?);
    let share_b = SharePoint::new(Point::from_scalar(Scalar::from(17_u64))?);
    let inner = InnerSupport::new(vec![
        DeviceParticipant::new(device_b, Node::from_u64(2)?, share_b),
        DeviceParticipant::new(device_a, Node::from_u64(1)?, share_a),
    ])?;
    assert_eq!(inner.participants()[0].device(), device_a);
    assert_eq!(inner.coefficient(device_a)?.scalar(), Scalar::from(2_u64));
    assert_eq!(inner.coefficient(device_b)?.scalar(), -Scalar::ONE);

    let person_a = PersonId::new([3; 32]);
    let person_b = PersonId::new([4; 32]);
    let outer = OuterSupport::new(vec![
        PersonParticipant::new(
            person_b,
            Slot::new(2),
            Node::from_u64(2)?,
            MemberPoint::new(Point::try_from(share_b.element())?),
        ),
        PersonParticipant::new(
            person_a,
            Slot::new(1),
            Node::from_u64(1)?,
            MemberPoint::new(Point::try_from(share_a.element())?),
        ),
    ])?;
    assert_eq!(outer.participants()[0].person(), person_a);
    assert_eq!(outer.coefficient(person_a)?.scalar(), Scalar::from(2_u64));
    assert_eq!(outer.coefficient(person_b)?.scalar(), -Scalar::ONE);
    Ok(())
}

#[test]
fn supports_reject_duplicate_ids_slots_and_nodes() -> Result<(), Error> {
    let device = DeviceId::new([1; 32]);
    let share = SharePoint::new(Point::from_scalar(Scalar::ONE)?);
    let node = Node::from_u64(1)?;
    assert_eq!(
        InnerSupport::new(vec![
            DeviceParticipant::new(device, node, share),
            DeviceParticipant::new(device, Node::from_u64(2)?, share),
        ]),
        Err(Error::DuplicateParticipant)
    );
    assert_eq!(
        InnerSupport::new(vec![
            DeviceParticipant::new(device, node, share),
            DeviceParticipant::new(DeviceId::new([2; 32]), node, share),
        ]),
        Err(Error::DuplicateNode)
    );

    let member = MemberPoint::new(Point::try_from(share.element())?);
    assert_eq!(
        OuterSupport::new(vec![
            PersonParticipant::new(PersonId::new([1; 32]), Slot::new(1), node, member),
            PersonParticipant::new(
                PersonId::new([2; 32]),
                Slot::new(1),
                Node::from_u64(2)?,
                member,
            ),
        ]),
        Err(Error::DuplicateSlot)
    );
    Ok(())
}
