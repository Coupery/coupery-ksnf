//! Primitive and encoding tests.

#![cfg(feature = "secp256k1")]

use coupery_ksnf::Error;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::profile::Secp256k1;
use coupery_ksnf::shamir::{Node, Polynomial, interpolate_constant};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

#[test]
fn group_encodings_cover_identity_and_points() -> Result<(), Error> {
    let point = Point::<Secp256k1>::from_scalar(Scalar::from(7_u64))?;
    assert_eq!(Point::from_bytes(&point.to_bytes())?, point);

    assert_eq!(
        Element::<Secp256k1>::from_bytes(&Element::<Secp256k1>::identity().to_bytes())?,
        Element::<Secp256k1>::identity()
    );
    assert_eq!(
        Element::from_bytes(&Element::from(point).to_bytes())?,
        Element::from(point)
    );

    let mut bad_identity = Element::<Secp256k1>::identity().to_bytes();
    bad_identity[1] = 1;
    assert_eq!(
        Element::<Secp256k1>::from_bytes(&bad_identity),
        Err(Error::InvalidIdentity)
    );
    assert_eq!(
        Point::<Secp256k1>::from_scalar(Scalar::ZERO),
        Err(Error::IdentityPoint)
    );
    Ok(())
}

#[test]
fn shamir_reconstructs_from_any_threshold_support() -> Result<(), Error> {
    let polynomial = Polynomial::new(vec![Scalar::from(42_u64), Scalar::from(7_u64)])?;
    let nodes = [Node::from_u64(1)?, Node::from_u64(2)?, Node::from_u64(3)?];
    let shares = nodes.map(|node| polynomial.evaluate(node));

    for support in [[0, 1], [0, 2], [1, 2]] {
        let support_nodes = support.map(|index| nodes[index]);
        let support_values = support.map(|index| shares[index].expose(|value| *value));
        assert_eq!(
            interpolate_constant::<Secp256k1>(&support_nodes, &support_values)?,
            Scalar::from(42_u64)
        );
    }
    Ok(())
}

#[test]
fn polynomial_sampling_keeps_the_constant() -> Result<(), Error> {
    let mut rng = ChaCha20Rng::from_seed([7_u8; 32]);
    let constant = SecretScalar::<Secp256k1>::new(Scalar::from(17_u64));
    let polynomial = Polynomial::sample(3, &constant, &mut rng)?;
    assert_eq!(polynomial.len(), 3);

    let commitments = polynomial.commitments();
    assert_eq!(commitments[0], Element::from_scalar(Scalar::from(17_u64)));
    Ok(())
}

#[test]
fn shamir_rejects_invalid_supports() -> Result<(), Error> {
    assert_eq!(Node::<Secp256k1>::from_u64(0), Err(Error::ZeroNode));
    let node = Node::from_u64(1)?;
    assert_eq!(
        interpolate_constant::<Secp256k1>(&[node, node], &[Scalar::ONE, Scalar::ONE]),
        Err(Error::DuplicateNode)
    );
    assert_eq!(
        interpolate_constant::<Secp256k1>(&[node], &[]),
        Err(Error::LengthMismatch)
    );
    Ok(())
}
