#![allow(missing_docs)]

use coupery_ksnf::Error;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::encoding::{Decoder, Encoder};
use coupery_ksnf::hash::{self, Domain};
use coupery_ksnf::shamir::{Node, Polynomial, interpolate_constant};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

#[test]
fn group_encodings_cover_identity_and_points() -> Result<(), Error> {
    let point = Point::from_scalar(Scalar::from(7_u64))?;
    assert_eq!(Point::from_bytes(&point.to_bytes())?, point);

    assert_eq!(
        Element::from_bytes(&Element::IDENTITY.to_bytes())?,
        Element::IDENTITY
    );
    assert_eq!(
        Element::from_bytes(&Element::from(point).to_bytes())?,
        Element::from(point)
    );

    let mut bad_identity = Element::IDENTITY.to_bytes();
    bad_identity[1] = 1;
    assert_eq!(
        Element::from_bytes(&bad_identity),
        Err(Error::InvalidIdentity)
    );
    assert_eq!(Point::from_scalar(Scalar::ZERO), Err(Error::IdentityPoint));
    Ok(())
}

#[test]
fn canonical_reader_rejects_truncation_and_trailing_bytes() -> Result<(), Error> {
    let scalar = Scalar::from(9_u64);
    let point = Point::from_scalar(Scalar::from(11_u64))?;
    let mut encoder = Encoder::new();
    encoder.put_u8(1);
    encoder.put_bytes(b"ksnf")?;
    encoder.put_scalar(&scalar);
    encoder.put_point(point);
    let bytes = encoder.finish();

    let mut decoder = Decoder::new(&bytes);
    assert_eq!(decoder.get_u8()?, 1);
    assert_eq!(decoder.get_bytes()?, b"ksnf");
    assert_eq!(decoder.get_scalar()?, scalar);
    assert_eq!(decoder.get_point()?, point);
    decoder.finish()?;

    let mut truncated = Decoder::new(&bytes[..bytes.len() - 1]);
    assert_eq!(truncated.get_u8()?, 1);
    assert_eq!(truncated.get_bytes()?, b"ksnf");
    assert_eq!(truncated.get_scalar()?, scalar);
    assert!(matches!(
        truncated.get_point(),
        Err(Error::UnexpectedEnd { .. })
    ));

    let mut with_trailer = bytes;
    with_trailer.push(0);
    let mut decoder = Decoder::new(&with_trailer);
    assert_eq!(decoder.get_u8()?, 1);
    assert_eq!(decoder.get_bytes()?, b"ksnf");
    assert_eq!(decoder.get_scalar()?, scalar);
    assert_eq!(decoder.get_point()?, point);
    assert!(matches!(decoder.finish(), Err(Error::TrailingBytes { .. })));
    Ok(())
}

#[test]
fn hash_domains_are_stable_and_distinct() -> Result<(), Error> {
    let message = b"coupery-ksnf";
    let outputs = [
        Domain::Deal,
        Domain::Member,
        Domain::Nonce,
        Domain::Bind,
        Domain::Challenge,
    ]
    .map(|domain| hash::to_scalar(domain, message))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    for (i, output) in outputs.iter().enumerate() {
        assert!(!outputs[..i].contains(output));
    }

    let actual = outputs.iter().map(scalar_hex).collect::<Vec<_>>();
    assert_eq!(
        actual,
        [
            "8e7329b6c0000ddd0251a73c17b1fac1aec8983a92dd358582e289c9f8021bf5",
            "d56eb6cdfaba507dc1c8bccb131094c1bd84d31369f7f6f3a127eade8ff6c184",
            "258f61650d54e60d33eb587e37d423948795161e438f33b0efb9b1cdf0e84c06",
            "bf0b18eef6d140af37fca842d45c1f84cb1178d568bdb413f16e5451457b12d3",
            "c24984385bc5328deaa812f9fa47b530247d90f0bec17196db87c31abb522581",
        ]
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
            interpolate_constant(&support_nodes, &support_values)?,
            Scalar::from(42_u64)
        );
    }
    Ok(())
}

#[test]
fn polynomial_sampling_keeps_the_constant() -> Result<(), Error> {
    let mut rng = ChaCha20Rng::from_seed([7_u8; 32]);
    let constant = SecretScalar::new(Scalar::from(17_u64));
    let polynomial = Polynomial::sample(3, &constant, &mut rng)?;
    assert_eq!(polynomial.len(), 3);

    let commitments = polynomial.commitments();
    assert_eq!(commitments[0], Element::from_scalar(Scalar::from(17_u64)));
    Ok(())
}

#[test]
fn shamir_rejects_invalid_supports() -> Result<(), Error> {
    assert_eq!(Node::from_u64(0), Err(Error::ZeroNode));
    let node = Node::from_u64(1)?;
    assert_eq!(
        interpolate_constant(&[node, node], &[Scalar::ONE, Scalar::ONE]),
        Err(Error::DuplicateNode)
    );
    assert_eq!(
        interpolate_constant(&[node], &[]),
        Err(Error::LengthMismatch)
    );
    Ok(())
}

#[test]
fn scalar_decoder_rejects_noncanonical_bytes() {
    let mut decoder = Decoder::new(&[0xff; 32]);
    assert_eq!(decoder.get_scalar(), Err(Error::InvalidScalar));
}

fn scalar_hex(scalar: &Scalar) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(64);
    for byte in scalar.to_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
