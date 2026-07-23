#![allow(missing_docs)]

use coupery_ksnf::Error;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::keys::{SharePoint, anchor_share, signing_share, verify_anchor};

#[test]
fn affine_translation_preserves_the_member_share() -> Result<(), Error> {
    let identity = SecretScalar::new(Scalar::from(13_u64));
    let member = SecretScalar::new(Scalar::from(29_u64));
    let anchor = anchor_share(&member, &identity);
    let recomputed = signing_share(&identity, &anchor);

    recomputed.expose(|value| assert_eq!(*value, Scalar::from(29_u64)));

    let identity_point = SharePoint::new(Point::from_scalar(Scalar::from(13_u64))?);
    let member_point = SharePoint::new(Point::from_scalar(Scalar::from(29_u64))?);
    assert!(verify_anchor(
        identity_point,
        Element::from_scalar(Scalar::from(16_u64)),
        member_point
    ));
    Ok(())
}
